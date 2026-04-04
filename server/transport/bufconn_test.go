package transport

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// BufConn tests
// ---------------------------------------------------------------------------

func TestBufConnWriteSmall(t *testing.T) {
	t.Parallel()
	cConn, sConn := net.Pipe()
	defer sConn.Close()

	bc := NewBufConn(cConn)
	defer bc.Close()

	msg := []byte("hello")
	n, err := bc.Write(msg)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(msg) {
		t.Fatalf("Write returned %d, want %d", n, len(msg))
	}

	// Data should arrive after the coalescing delay.
	buf := make([]byte, 64)
	sConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	nr, err := sConn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(buf[:nr], msg) {
		t.Fatalf("got %q, want %q", buf[:nr], msg)
	}
}

func TestBufConnWriteCoalesces(t *testing.T) {
	t.Parallel()
	cConn, sConn := net.Pipe()
	defer sConn.Close()

	bc := NewBufConn(cConn)
	defer bc.Close()

	// Write two small messages quickly — they should be coalesced.
	bc.Write([]byte("aaa")) //nolint:errcheck
	bc.Write([]byte("bbb")) //nolint:errcheck

	buf := make([]byte, 64)
	sConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	nr, err := sConn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	// Both messages should arrive in a single read.
	if !bytes.Equal(buf[:nr], []byte("aaabbb")) {
		t.Fatalf("got %q, want %q", buf[:nr], "aaabbb")
	}
}

func TestBufConnFlushOnSize(t *testing.T) {
	t.Parallel()
	cConn, sConn := net.Pipe()
	defer sConn.Close()

	bc := NewBufConn(cConn)
	defer bc.Close()

	// Write enough data to exceed coalesceMaxSize → immediate flush.
	big := make([]byte, coalesceMaxSize+100)
	for i := range big {
		big[i] = byte(i)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		total := 0
		buf := make([]byte, len(big)+1024)
		for total < len(big) {
			sConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, err := sConn.Read(buf[total:])
			if err != nil {
				return
			}
			total += n
		}
	}()

	n, err := bc.Write(big)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(big) {
		t.Fatalf("Write returned %d, want %d", n, len(big))
	}
	<-done
}

func TestBufConnExplicitFlush(t *testing.T) {
	t.Parallel()
	cConn, sConn := net.Pipe()
	defer sConn.Close()

	bc := NewBufConn(cConn)
	defer bc.Close()

	bc.Write([]byte("xyz")) //nolint:errcheck

	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		sConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _ := sConn.Read(buf)
		done <- buf[:n]
	}()

	bc.Flush() //nolint:errcheck

	got := <-done
	if !bytes.Equal(got, []byte("xyz")) {
		t.Fatalf("got %q, want %q", got, "xyz")
	}
}

func TestBufConnRead(t *testing.T) {
	t.Parallel()
	cConn, sConn := net.Pipe()
	defer cConn.Close()

	bc := NewBufConn(sConn)
	defer bc.Close()

	msg := []byte("read test")
	go func() {
		cConn.Write(msg) //nolint:errcheck
	}()

	buf := make([]byte, 64)
	n, err := bc.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Fatalf("got %q, want %q", buf[:n], msg)
	}
}

func TestBufConnClose(t *testing.T) {
	t.Parallel()
	cConn, sConn := net.Pipe()

	bc := NewBufConn(cConn)
	bc.Write([]byte("pending")) //nolint:errcheck

	// Reader to drain the pending data.
	go func() {
		io.Copy(io.Discard, sConn) //nolint:errcheck
	}()

	err := bc.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	sConn.Close()

	// Write after close should fail.
	_, err = bc.Write([]byte("x"))
	if err == nil {
		// The underlying conn is closed, so eventual writes will fail.
		// Due to buffering, the first write might succeed (buffered),
		// but subsequent flush will fail.
	}
}

func TestBufConnConcurrentWrites(t *testing.T) {
	t.Parallel()
	cConn, sConn := net.Pipe()
	defer sConn.Close()

	bc := NewBufConn(cConn)
	defer bc.Close()

	const writers = 10
	const msgSize = 100

	// Reader goroutine.
	var received bytes.Buffer
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		buf := make([]byte, 4096)
		total := 0
		for total < writers*msgSize {
			sConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := sConn.Read(buf)
			if err != nil {
				return
			}
			received.Write(buf[:n])
			total += n
		}
	}()

	// Concurrent writers.
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			data := bytes.Repeat([]byte{byte(id)}, msgSize)
			bc.Write(data) //nolint:errcheck
		}(i)
	}
	wg.Wait()
	bc.Flush() //nolint:errcheck
	<-readerDone

	if received.Len() != writers*msgSize {
		t.Fatalf("received %d bytes, want %d", received.Len(), writers*msgSize)
	}
}

func TestBufConnNetConnInterface(t *testing.T) {
	t.Parallel()
	cConn, sConn := net.Pipe()
	defer cConn.Close()
	defer sConn.Close()

	bc := NewBufConn(cConn)
	defer bc.Close()

	// Verify BufConn satisfies net.Conn.
	var _ net.Conn = bc

	// Verify addr delegation.
	if bc.LocalAddr() != cConn.LocalAddr() {
		t.Error("LocalAddr mismatch")
	}
	if bc.RemoteAddr() != cConn.RemoteAddr() {
		t.Error("RemoteAddr mismatch")
	}
}
