package transport

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// newMuxPair creates two connected Mux objects backed by net.Pipe.
// Returns (client, server).
func newMuxPair(t *testing.T) (*Mux, *Mux) {
	t.Helper()
	cConn, sConn := net.Pipe()
	client := NewMux(cConn, true)
	server := NewMux(sConn, false)
	return client, server
}

// ---------------------------------------------------------------------------
// Stream open / accept
// ---------------------------------------------------------------------------

func TestMuxOpenAcceptStream(t *testing.T) {
	client, server := newMuxPair(t)
	defer client.Close()
	defer server.Close()

	var (
		sStream *Stream
		sErr    error
		wg      sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		sStream, sErr = server.AcceptStream(ctx)
	}()

	cStream, err := client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	wg.Wait()

	if sErr != nil {
		t.Fatalf("AcceptStream: %v", sErr)
	}
	if sStream == nil {
		t.Fatal("AcceptStream returned nil stream")
	}
	cStream.Close()
	sStream.Close()
}

func TestMuxStreamIDNamespaces(t *testing.T) {
	client, server := newMuxPair(t)
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	var accepted *Stream
	go func() {
		defer wg.Done()
		var err error
		accepted, err = server.AcceptStream(ctx)
		if err != nil {
			t.Errorf("AcceptStream: %v", err)
		}
	}()

	opened, err := client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	wg.Wait()

	// Client-opened streams must be even; server-opened must be odd.
	if opened.ID()%2 != 0 {
		t.Errorf("client stream ID %d should be even", opened.ID())
	}
	if accepted.ID()%2 != 0 {
		t.Errorf("accepted stream ID %d should be even (mirrors client's even ID)", accepted.ID())
	}

	// Now let the server open a stream and the client accept.
	wg.Add(1)
	var cAccepted *Stream
	go func() {
		defer wg.Done()
		var err error
		cAccepted, err = client.AcceptStream(ctx)
		if err != nil {
			t.Errorf("AcceptStream on client: %v", err)
		}
	}()

	sOpened, err := server.OpenStream()
	if err != nil {
		t.Fatalf("server OpenStream: %v", err)
	}
	wg.Wait()

	if sOpened.ID()%2 == 0 {
		t.Errorf("server stream ID %d should be odd", sOpened.ID())
	}
	if cAccepted.ID()%2 == 0 {
		t.Errorf("client-accepted stream ID %d should be odd", cAccepted.ID())
	}

	opened.Close()
	accepted.Close()
	sOpened.Close()
	cAccepted.Close()
}

// ---------------------------------------------------------------------------
// Data transfer
// ---------------------------------------------------------------------------

func TestMuxStreamWriteRead(t *testing.T) {
	client, server := newMuxPair(t)
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	msg := []byte("hello mux")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s, err := server.AcceptStream(ctx)
		if err != nil {
			t.Errorf("AcceptStream: %v", err)
			return
		}
		defer s.Close()
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(s, buf); err != nil {
			t.Errorf("ReadFull: %v", err)
			return
		}
		if !bytes.Equal(buf, msg) {
			t.Errorf("got %q, want %q", buf, msg)
		}
	}()

	cs, err := client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer cs.Close()

	if _, err := cs.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	wg.Wait()
}

func TestMuxStreamBidirectional(t *testing.T) {
	client, server := newMuxPair(t)
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ping := []byte("ping")
	pong := []byte("pong")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s, err := server.AcceptStream(ctx)
		if err != nil {
			t.Errorf("AcceptStream: %v", err)
			return
		}
		defer s.Close()
		buf := make([]byte, len(ping))
		if _, err := io.ReadFull(s, buf); err != nil {
			t.Errorf("server ReadFull: %v", err)
			return
		}
		if !bytes.Equal(buf, ping) {
			t.Errorf("server got %q, want %q", buf, ping)
		}
		if _, err := s.Write(pong); err != nil {
			t.Errorf("server Write: %v", err)
		}
	}()

	cs, err := client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer cs.Close()

	if _, err := cs.Write(ping); err != nil {
		t.Fatalf("client Write: %v", err)
	}
	buf := make([]byte, len(pong))
	if _, err := io.ReadFull(cs, buf); err != nil {
		t.Fatalf("client ReadFull: %v", err)
	}
	if !bytes.Equal(buf, pong) {
		t.Fatalf("client got %q, want %q", buf, pong)
	}
	wg.Wait()
}

func TestMuxMultipleStreams(t *testing.T) {
	const numStreams = 5
	client, server := newMuxPair(t)
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var wg sync.WaitGroup

	// Server: accept numStreams streams, echo each message back.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numStreams; i++ {
			s, err := server.AcceptStream(ctx)
			if err != nil {
				t.Errorf("AcceptStream %d: %v", i, err)
				return
			}
			wg.Add(1)
			go func(s *Stream) {
				defer wg.Done()
				defer s.Close()
				buf := make([]byte, 64)
				n, err := s.Read(buf)
				if err != nil {
					t.Errorf("server Read: %v", err)
					return
				}
				if _, err := s.Write(buf[:n]); err != nil {
					t.Errorf("server Write: %v", err)
				}
			}(s)
		}
	}()

	// Client: open numStreams streams and verify echo.
	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, err := client.OpenStream()
			if err != nil {
				t.Errorf("OpenStream %d: %v", i, err)
				return
			}
			defer s.Close()
			msg := []byte("stream message")
			if _, err := s.Write(msg); err != nil {
				t.Errorf("client Write %d: %v", i, err)
				return
			}
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(s, buf); err != nil {
				t.Errorf("client ReadFull %d: %v", i, err)
				return
			}
			if !bytes.Equal(buf, msg) {
				t.Errorf("stream %d: got %q, want %q", i, buf, msg)
			}
		}(i)
	}
	wg.Wait()
}

func TestMuxLargePayload(t *testing.T) {
	client, server := newMuxPair(t)
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 200 KB — exceeds maxMuxPayload (65535), forcing fragmentation.
	data := make([]byte, 200*1024)
	for i := range data {
		data[i] = byte(i)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s, err := server.AcceptStream(ctx)
		if err != nil {
			t.Errorf("AcceptStream: %v", err)
			return
		}
		defer s.Close()
		received := make([]byte, len(data))
		if _, err := io.ReadFull(s, received); err != nil {
			t.Errorf("ReadFull: %v", err)
			return
		}
		if !bytes.Equal(received, data) {
			t.Error("large payload mismatch")
		}
	}()

	cs, err := client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer cs.Close()
	if _, err := cs.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Stream closure
// ---------------------------------------------------------------------------

func TestMuxStreamCloseSignalsEOF(t *testing.T) {
	client, server := newMuxPair(t)
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s, err := server.AcceptStream(ctx)
		if err != nil {
			t.Errorf("AcceptStream: %v", err)
			return
		}
		// Read until EOF.
		buf := make([]byte, 64)
		_, err = s.Read(buf)
		if err != io.EOF {
			t.Errorf("expected io.EOF, got %v", err)
		}
	}()

	cs, err := client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	// Close without writing any data — remote should see EOF.
	cs.Close()
	wg.Wait()
}

func TestMuxStreamWriteAfterCloseErrors(t *testing.T) {
	client, server := newMuxPair(t)
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		s, err := server.AcceptStream(ctx)
		if err == nil {
			s.Close()
		}
	}()

	cs, err := client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	cs.Close()

	_, err = cs.Write([]byte("should fail"))
	if err == nil {
		t.Fatal("expected error writing to closed stream")
	}
}

func TestMuxStreamCloseIdempotent(t *testing.T) {
	client, server := newMuxPair(t)
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		s, err := server.AcceptStream(ctx)
		if err == nil {
			s.Close()
		}
	}()

	cs, err := client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	// Multiple Close calls must not panic.
	cs.Close()
	cs.Close()
	cs.Close()
}

// ---------------------------------------------------------------------------
// Mux closure
// ---------------------------------------------------------------------------

func TestMuxCloseUnblocksAccept(t *testing.T) {
	client, server := newMuxPair(t)
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err := server.AcceptStream(ctx)
		done <- err
	}()

	server.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error after mux close, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AcceptStream did not unblock after mux close")
	}
}

func TestMuxCloseUnblocksStreamRead(t *testing.T) {
	client, server := newMuxPair(t)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var accepted *Stream
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error
		accepted, err = server.AcceptStream(ctx)
		if err != nil {
			t.Errorf("AcceptStream: %v", err)
		}
	}()

	cs, err := client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	wg.Wait()
	if accepted == nil {
		t.Fatal("no accepted stream")
	}

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		_, err := accepted.Read(buf)
		done <- err
	}()

	// Closing the client mux should cause the underlying conn to close,
	// which forces the server's readLoop to stop and unblock reads.
	client.Close()
	cs.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error on Read after remote mux close, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read did not unblock after remote mux close")
	}
}

// ---------------------------------------------------------------------------
// AcceptStream context cancellation
// ---------------------------------------------------------------------------

func TestMuxAcceptStreamContextCancelled(t *testing.T) {
	_, server := newMuxPair(t)
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := server.AcceptStream(ctx)
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
}

// ---------------------------------------------------------------------------
// Read buffering
// ---------------------------------------------------------------------------

func TestMuxStreamReadBuffering(t *testing.T) {
	client, server := newMuxPair(t)
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	msg := []byte("0123456789")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s, err := server.AcceptStream(ctx)
		if err != nil {
			t.Errorf("AcceptStream: %v", err)
			return
		}
		defer s.Close()
		// Read in small chunks to exercise the internal readBuf path.
		var got []byte
		buf := make([]byte, 3)
		for len(got) < len(msg) {
			n, err := s.Read(buf)
			if err != nil && err != io.EOF {
				t.Errorf("Read: %v", err)
				return
			}
			got = append(got, buf[:n]...)
		}
		if !bytes.Equal(got, msg) {
			t.Errorf("got %q, want %q", got, msg)
		}
	}()

	cs, err := client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer cs.Close()
	if _, err := cs.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Frame header helpers
// ---------------------------------------------------------------------------

func TestMuxFrameHeaderEncoding(t *testing.T) {
	cConn, sConn := net.Pipe()
	defer cConn.Close()
	defer sConn.Close()

	client := NewMux(cConn, true)
	defer client.Close()

	// Send a raw frame and verify the 7-byte header on the other side.
	go func() {
		client.writeFrame(42, FrameData, []byte("hi")) //nolint:errcheck
	}()

	hdr := make([]byte, muxHeaderSize)
	if _, err := io.ReadFull(sConn, hdr); err != nil {
		t.Fatalf("ReadFull header: %v", err)
	}

	streamID := (uint32(hdr[0]) << 24) | (uint32(hdr[1]) << 16) | (uint32(hdr[2]) << 8) | uint32(hdr[3])
	if streamID != 42 {
		t.Errorf("streamID %d, want 42", streamID)
	}
	if hdr[4] != FrameData {
		t.Errorf("frame type %02x, want FrameData %02x", hdr[4], FrameData)
	}
	length := (uint16(hdr[5]) << 8) | uint16(hdr[6])
	if length != 2 {
		t.Errorf("length %d, want 2", length)
	}
}
