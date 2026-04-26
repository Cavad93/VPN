// Package transport — batch.go provides batched UDP send/receive operations.
//
// Instead of one syscall per packet (WriteToUDP/ReadFromUDP), batch operations
// amortize syscall overhead by sending/receiving multiple packets at once.
//
// Platform-specific implementations (batch_linux.go, etc.) use sendmmsg/recvmmsg
// when available. This file provides the cross-platform fallback that works
// everywhere (Windows, macOS, Linux) using a simple loop.
package transport

import "net"

// maxBatchSize is the maximum number of packets per batch operation.
// 64 matches the typical Linux sendmmsg/recvmmsg limit and provides
// good amortization of syscall overhead.
const maxBatchSize = 64

// batchMsg holds one outgoing packet destined for a specific remote address.
type batchMsg struct {
	buf    []byte
	addr   *net.UDPAddr
	poolBp *[]byte // if non-nil, return to sendBufPool after send
}

// batchResult holds one received packet from a batch read.
//
// key replaces the previous addr *net.UDPAddr field. Pre-computing the
// udpAddrKey inside readPlatform (from raw sockaddr on Linux, or from the
// ReadFromUDP result on other platforms) eliminates net.IPv4() + &net.UDPAddr{}
// heap allocations on the hot receive path (~2630 allocs/sec at 30 Mbps).
// The key is used directly for the O(1) map lookup in readLoop; a *net.UDPAddr
// is reconstructed via key.toUDPAddr() only for new connections (infrequent).
type batchResult struct {
	n   int
	key udpAddrKey // pre-computed remote address key; no heap allocation
	buf []byte     // slice into the pre-allocated buffer
}

// batchWriter accumulates outgoing packets and flushes them in one batch.
type batchWriter struct {
	conn *net.UDPConn
	msgs []batchMsg
}

// newBatchWriter creates a batch writer for the given UDP connection.
func newBatchWriter(conn *net.UDPConn) *batchWriter {
	return &batchWriter{
		conn: conn,
		msgs: make([]batchMsg, 0, maxBatchSize),
	}
}

// Add queues a packet for the next flush. The buffer must remain valid
// until Flush returns.
func (w *batchWriter) Add(buf []byte, addr *net.UDPAddr, poolBp *[]byte) {
	w.msgs = append(w.msgs, batchMsg{buf: buf, addr: addr, poolBp: poolBp})
}

// Len returns the number of queued packets.
func (w *batchWriter) Len() int {
	return len(w.msgs)
}

// Flush sends all queued packets via the platform-optimal method.
// Returns pool buffers to sendBufPool after sending.
// On error, returns the first error encountered but still attempts
// to send remaining packets and return all pool buffers.
func (w *batchWriter) Flush() error {
	if len(w.msgs) == 0 {
		return nil
	}
	err := w.flushPlatform()
	// Return all pool buffers regardless of error.
	for i := range w.msgs {
		if w.msgs[i].poolBp != nil {
			sendBufPool.Put(w.msgs[i].poolBp)
			w.msgs[i].poolBp = nil
		}
	}
	w.msgs = w.msgs[:0]
	return err
}

// Reset discards all queued packets and returns pool buffers.
func (w *batchWriter) Reset() {
	for i := range w.msgs {
		if w.msgs[i].poolBp != nil {
			sendBufPool.Put(w.msgs[i].poolBp)
			w.msgs[i].poolBp = nil
		}
	}
	w.msgs = w.msgs[:0]
}

// batchReader reads multiple packets from a UDP socket in one operation.
type batchReader struct {
	conn   *net.UDPConn
	bufs   [][]byte                  // pre-allocated receive buffers
	resBuf [maxBatchSize]batchResult // persistent results buffer — avoids make() per batch
}

// newBatchReader creates a batch reader with pre-allocated buffers.
func newBatchReader(conn *net.UDPConn, count int) *batchReader {
	if count > maxBatchSize {
		count = maxBatchSize
	}
	bufs := make([][]byte, count)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	return &batchReader{
		conn: conn,
		bufs: bufs,
	}
}

// Read reads up to len(bufs) packets in one batch operation.
// Returns the results and count of packets read.
// Uses platform-optimal batch receive when available.
func (r *batchReader) Read() ([]batchResult, int, error) {
	return r.readPlatform()
}
