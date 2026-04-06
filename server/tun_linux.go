//go:build linux

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	tunDevice = "/dev/net/tun"
	iffTun    = 0x0001
	iffNoPi   = 0x1000

	// tunMTU is the MTU configured on the TUN interface.
	//
	// Every inner IP packet is wrapped in VPN framing before being handed to the
	// UDP transport layer (transport.Conn.Write). The transport splits data into
	// MaxPayloadSize (1460-byte) chunks, each tracked independently as one entry
	// in the BBR congestion window (cwnd). A split wastes one cwnd slot on a tiny
	// fragment, halving effective throughput at any given cwnd value.
	//
	// VPN framing overhead per inner IP packet:
	//   mux header:        7 bytes  (streamID + type + length)
	//   noise length:      2 bytes  (BE uint16 frame length)
	//   noise AEAD tag:   16 bytes  (ChaCha20-Poly1305 authentication tag)
	//   obfs TLS header:   5 bytes  (content_type + version + length)
	//   total overhead:   30 bytes
	//
	// To avoid splitting, the obfs TLS record must fit in one UDP payload:
	//   inner_IP + 30 ≤ MaxPayloadSize (1460)
	//   inner_IP ≤ 1430
	//
	// Setting tunMTU = 1430 guarantees that every inner IP packet produces
	// exactly ONE UDP datagram. This doubles the effective cwnd capacity
	// compared to tunMTU = 1460 (which produces 2 datagrams per IP packet).
	tunMTU = 1430
)

// tunIfreq is the ifreq structure for TUNSETIFF ioctl.
type tunIfreq struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}

// tunIfreqMTU is the ifreq structure for SIOCSIFMTU ioctl.
// The MTU field overlaps with the flags field in the union.
type tunIfreqMTU struct {
	name [16]byte
	mtu  int32
	_    [18]byte
}

// linuxTun implements TunDevice using Linux's /dev/net/tun.
type linuxTun struct {
	file *os.File
}

// OpenTun opens (or creates) a TUN device with the given name.
func OpenTun(name string) (TunDevice, error) {
	f, err := os.OpenFile(tunDevice, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("OpenTun: open %s: %w", tunDevice, err)
	}

	var ifr tunIfreq
	if len(name) >= len(ifr.name) {
		f.Close()
		return nil, fmt.Errorf("OpenTun: interface name %q too long", name)
	}
	copy(ifr.name[:], name)
	ifr.flags = iffTun | iffNoPi

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		syscall.TUNSETIFF,
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		f.Close()
		return nil, fmt.Errorf("OpenTun: TUNSETIFF ioctl: %w", errno)
	}

	// Set MTU via SIOCSIFMTU on a temporary UDP socket (standard approach).
	// We need a real network socket, not the TUN fd, for SIOCSIFMTU.
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err == nil {
		var mtuReq tunIfreqMTU
		copy(mtuReq.name[:], name)
		mtuReq.mtu = tunMTU
		syscall.Syscall( //nolint:errcheck — best-effort; kernel uses 1500 if this fails
			syscall.SYS_IOCTL,
			uintptr(sock),
			syscall.SIOCSIFMTU,
			uintptr(unsafe.Pointer(&mtuReq)),
		)
		syscall.Close(sock)
	}

	return &linuxTun{file: f}, nil
}

func (t *linuxTun) Read(p []byte) (int, error)  { return t.file.Read(p) }
func (t *linuxTun) Write(p []byte) (int, error) { return t.file.Write(p) }
func (t *linuxTun) Close() error                { return t.file.Close() }
