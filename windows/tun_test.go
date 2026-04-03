package main

import (
	"errors"
	"testing"
	"time"
)

func TestOpenTun_ReturnsError(t *testing.T) {
	_, err := OpenTun(TunConfig{
		Name:      "utun99",
		LocalIP:   "10.8.0.2",
		GatewayIP: "10.8.0.1",
		PrefixLen: 24,
		MTU:       1420,
	})
	if err == nil {
		t.Error("OpenTun should return error on non-Windows platform")
	}
	// On non-Windows should wrap ErrNotWindows
	if !errors.Is(err, ErrNotWindows) {
		t.Errorf("OpenTun error should wrap ErrNotWindows, got: %v", err)
	}
}

func TestMockTun_WriteRead(t *testing.T) {
	tunA, tunB := NewMockTun()
	defer tunA.Close()
	defer tunB.Close()

	pkt := []byte{0x45, 0x00, 0x00, 0x28} // fake IP header

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		n, err := tunB.Read(buf)
		if err != nil {
			return
		}
		if string(buf[:n]) != string(pkt) {
			return
		}
	}()

	n, err := tunA.Write(pkt)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(pkt) {
		t.Errorf("Write: wrote %d bytes, want %d", n, len(pkt))
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("timeout waiting for Read")
	}
}

func TestMockTun_ReadAfterClose(t *testing.T) {
	tunA, _ := NewMockTun()

	if err := tunA.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Read should return an error after close
	buf := make([]byte, 1500)
	_, err := tunA.Read(buf)
	if err == nil {
		t.Error("Read should fail after Close")
	}
}

func TestMockTun_WriteAfterClose(t *testing.T) {
	tunA, _ := NewMockTun()

	if err := tunA.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Write should return an error after close
	_, err := tunA.Write([]byte{1, 2, 3})
	if err == nil {
		t.Error("Write should fail after Close")
	}
}

func TestMockTun_CloseIdempotent(t *testing.T) {
	tunA, tunB := NewMockTun()

	// Multiple closes should not panic
	if err := tunA.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// Closing B which shares the done channel
	if err := tunB.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestMockTun_BidirectionalFlow(t *testing.T) {
	tunA, tunB := NewMockTun()
	defer tunA.Close()
	defer tunB.Close()

	// A→B
	pkt1 := []byte("packet from A")
	done1 := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1500)
		n, _ := tunB.Read(buf)
		done1 <- buf[:n]
	}()
	tunA.Write(pkt1)

	// B→A
	pkt2 := []byte("packet from B")
	done2 := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1500)
		n, _ := tunA.Read(buf)
		done2 <- buf[:n]
	}()
	tunB.Write(pkt2)

	select {
	case got := <-done1:
		if string(got) != string(pkt1) {
			t.Errorf("A→B: got %q, want %q", got, pkt1)
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout reading from B")
	}

	select {
	case got := <-done2:
		if string(got) != string(pkt2) {
			t.Errorf("B→A: got %q, want %q", got, pkt2)
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout reading from A")
	}
}

func TestTunConfig(t *testing.T) {
	cfg := TunConfig{
		Name:      "utun0",
		LocalIP:   "10.8.0.2",
		GatewayIP: "10.8.0.1",
		PrefixLen: 24,
		MTU:       1420,
	}
	if cfg.Name != "utun0" {
		t.Errorf("Name: got %s", cfg.Name)
	}
	if cfg.MTU != 1420 {
		t.Errorf("MTU: got %d", cfg.MTU)
	}
}
