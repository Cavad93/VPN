//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

// windowsTun implements TunDevice using the Wintun kernel driver.
// Wintun provides a high-performance TUN interface on Windows without TAP-Windows.
// The wintun.dll must reside in the same directory as the server binary.
type windowsTun struct {
	adapter    *wintun.Adapter
	session    wintun.Session
	closeEvent windows.Handle
	closeOnce  sync.Once
	wrMu       sync.Mutex // AllocateSendPacket+SendPacket are NOT thread-safe;
	// without this lock, 32 handleDataStream goroutines corrupt the Wintun send
	// ring buffer concurrently, producing garbled IP packets that TCP rejects as
	// bad checksums — identical to the macOS wrBuf race fixed in tun_darwin.go.
}

// OpenTun creates a Wintun TUN adapter with the given name and starts a session.
// The adapter is created with tunnel type "CavadVPN". If an adapter with the same
// name already exists it is reused; CreateAdapter is idempotent when the GUID is nil.
//
// Requires: wintun.dll in the same directory as the executable, and administrator
// privileges (Wintun installs a kernel driver on first use).
func OpenTun(name string) (TunDevice, error) {
	adapter, err := wintun.CreateAdapter(name, "CavadVPN", nil)
	if err != nil {
		return nil, fmt.Errorf("OpenTun: CreateAdapter %q: %w", name, err)
	}

	// 0x800000 = 8 MiB ring buffer — enough headroom for VPN traffic bursts.
	session, err := adapter.StartSession(0x800000)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("OpenTun: StartSession: %w", err)
	}

	// Manual-reset event (initial state: not signaled).
	// Signaled by Close() to unblock a pending Read().
	closeEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		session.End()
		adapter.Close()
		return nil, fmt.Errorf("OpenTun: CreateEvent: %w", err)
	}

	return &windowsTun{
		adapter:    adapter,
		session:    session,
		closeEvent: closeEvent,
	}, nil
}

// Read blocks until an IP packet is available from the TUN adapter, then copies
// it into p. Returns io.EOF when the adapter is closed.
func (t *windowsTun) Read(p []byte) (int, error) {
	for {
		packet, err := t.session.ReceivePacket()
		if err == nil {
			n := copy(p, packet)
			t.session.ReleaseReceivePacket(packet)
			return n, nil
		}

		if !errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			return 0, fmt.Errorf("windowsTun: ReceivePacket: %w", err)
		}

		// No packet available — wait on either the Wintun read-event or our
		// close-event. WaitForMultipleObjects returns the index of the first
		// signaled handle (0 = new packet, 1 = close).
		handles := []windows.Handle{t.session.ReadWaitEvent(), t.closeEvent}
		event, waitErr := windows.WaitForMultipleObjects(handles, false, windows.INFINITE)
		if waitErr != nil {
			return 0, fmt.Errorf("windowsTun: WaitForMultipleObjects: %w", waitErr)
		}
		if event == 1 {
			// Close event was signaled.
			return 0, io.EOF
		}
		// event == 0: Wintun has a packet ready — loop back to ReceivePacket.
	}
}

// Write sends an IP packet through the TUN adapter.
//
// wrMu serialises concurrent calls: the Wintun C library ring buffer is not
// thread-safe for concurrent writers.  Without this lock, 32 goroutines from
// handleDataStream (one per bond stream) call AllocateSendPacket and SendPacket
// simultaneously, overwriting each other's ring-buffer slots and producing
// corrupted IP packets.  The kernel drops them as bad checksums, which TCP
// misinterprets as congestion loss, halving every connection's CWND — the
// primary cause of throughput being ~50% of theoretical maximum.
func (t *windowsTun) Write(p []byte) (int, error) {
	t.wrMu.Lock()
	packet, err := t.session.AllocateSendPacket(len(p))
	if err != nil {
		t.wrMu.Unlock()
		return 0, fmt.Errorf("windowsTun: AllocateSendPacket: %w", err)
	}
	copy(packet, p)
	t.session.SendPacket(packet)
	t.wrMu.Unlock()
	return len(p), nil
}

// Close signals the read loop, ends the Wintun session and closes the adapter.
// Safe to call multiple times.
func (t *windowsTun) Close() error {
	t.closeOnce.Do(func() {
		// Unblock any Read() goroutine.
		windows.SetEvent(t.closeEvent) //nolint:errcheck
		t.session.End()
		windows.CloseHandle(t.closeEvent) //nolint:errcheck
		t.adapter.Close()
	})
	return nil
}
