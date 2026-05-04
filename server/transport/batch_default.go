//go:build !linux

// Package transport — batch_default.go provides fallback batch I/O
// using a simple loop of individual syscalls. Works on all platforms
// (Windows, macOS).
//
// On Linux, batch_linux.go provides sendmmsg/recvmmsg for true
// kernel-level batching.
package transport

// batchWriterPlatform holds pre-allocated send-side arrays for flushPlatform.
// On non-Linux platforms there is nothing to pre-allocate — this is a zero-size stub.
type batchWriterPlatform struct{}

// batchReaderPlatform holds pre-allocated receive-side arrays for readPlatform.
// On non-Linux platforms there is nothing to pre-allocate — this is a zero-size stub.
type batchReaderPlatform struct{}

// flushPlatform sends all queued packets using individual WriteToUDP calls.
// This is the cross-platform fallback — one syscall per packet.
func (w *batchWriter) flushPlatform() error {
	var firstErr error
	for _, msg := range w.msgs {
		_, err := w.conn.WriteToUDP(msg.buf, msg.addr)
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// readPlatform reads one packet at a time using ReadFromUDP.
// This is the cross-platform fallback — returns after each successful read.
func (r *batchReader) readPlatform() ([]batchResult, int, error) {
	n, addr, err := r.conn.ReadFromUDP(r.bufs[0])
	if err != nil {
		return nil, 0, err
	}
	r.resBuf[0] = batchResult{
		n:   n,
		key: makeUDPAddrKey(addr),
		buf: r.bufs[0][:n],
	}
	return r.resBuf[:1], 1, nil
}
