//go:build linux

// Package transport — batch_linux.go provides Linux-optimized batch I/O
// using sendmmsg(2) and recvmmsg(2) syscalls via golang.org/x/sys/unix.
//
// sendmmsg sends multiple UDP datagrams in a single syscall, reducing
// context switches from N to 1 per batch. This is the key optimization
// for user-space congestion control where per-packet syscall overhead
// is the primary bottleneck.
//
// Memory layout:
// All mmsghdr/iovec/sockaddr arrays used by sendmmsg and recvmmsg are embedded
// as VALUE arrays inside batchWriterPlatform / batchReaderPlatform, which are
// themselves embedded in batchWriter / batchReader. This means the arrays live
// in the same heap object as the connection, eliminating the per-flush allocations
// that previously occurred (~3 make() calls per Flush(), ~2630 calls/sec at 30 Mbps).
//
// Zero-allocation send path:
// The file descriptor is cached on the first flush (one-time rawConn.Control()
// call). Subsequent flushes call SYS_SENDMMSG via unix.Syscall6 directly,
// avoiding both the SyscallConn() allocation and the closure allocation that
// rawConn.Control() requires. The cached FD is valid for the lifetime of the
// *net.UDPConn held by w.conn; Close() of that conn invalidates the FD, but
// flushPlatform is never called after Close() (writePacket checks ctx.Err first).
package transport

import (
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// batchWriterPlatform embeds pre-allocated send-side arrays for sendmmsg and
// a cached file descriptor so that flushPlatform can call SYS_SENDMMSG directly
// without allocating a rawConn wrapper or a closure on every flush.
type batchWriterPlatform struct {
	// Pre-allocated fixed arrays — embedded as values, zero extra heap allocs.
	mmsghdrs  [maxBatchSize]mmsghdr
	iovecs    [maxBatchSize]unix.Iovec
	sockaddrs [maxBatchSize]unix.RawSockaddrInet4

	// fd is the cached socket file descriptor.
	// Set to non-zero once on the first flushPlatform call via rawConn.Control().
	// After that, all flushes use it directly (no SyscallConn, no closure).
	fd      uintptr
	fdReady bool // true once fd has been fetched
}

// batchReaderPlatform embeds pre-allocated receive-side arrays for recvmmsg.
// result and resultAddrs/resultIPs hold the decoded batchResult values that
// readPlatform returns — callers must not retain them across the next Read call.
type batchReaderPlatform struct {
	// Pre-allocated fixed arrays for recvmmsg.
	mmsghdrs  [maxBatchSize]mmsghdr
	iovecs    [maxBatchSize]unix.Iovec
	sockaddrs [maxBatchSize]unix.RawSockaddrInet4

	// results holds the decoded packets. Returned as a sub-slice; valid until
	// the next Read() call (same goroutine, sequential access).
	results [maxBatchSize]batchResult

	// resultAddrs is the pre-allocated net.UDPAddr storage reused per batch.
	resultAddrs [maxBatchSize]net.UDPAddr

	// resultIPs is the pre-allocated 16-byte IP backing for each UDPAddr.
	// Eliminates the net.IPv4() heap allocation (net.IP is a []byte).
	resultIPs [maxBatchSize][16]byte

	// rawConn is cached after the first readPlatform call to avoid calling
	// SyscallConn() (which allocates a new *rawConn) on every read.
	rawConn  syscall.RawConn
	rcReady  bool
}

// flushPlatform sends all queued packets using sendmmsg(2) — one syscall
// for up to 64 packets instead of 64 individual WriteToUDP calls.
//
// Steady-state (after first call): zero heap allocations.
//   - All mmsghdr/iovec/sockaddr arrays are pre-allocated in w.platform.
//   - The socket FD is cached in w.platform.fd; no SyscallConn() call.
//   - No closure is passed to rawConn.Control(); unix.Syscall6 is called directly.
//
// First call only: one rawConn.Control() to cache the FD (one-time cost).
func (w *batchWriter) flushPlatform() error {
	n := len(w.msgs)
	if n == 0 {
		return nil
	}

	// Fast path: single packet — use regular WriteToUDP (no mmsghdr overhead).
	if n == 1 {
		_, err := w.conn.WriteToUDP(w.msgs[0].buf, w.msgs[0].addr)
		return err
	}

	// Initialise the cached FD on the very first flush (one-time).
	if !w.platform.fdReady {
		rawConn, err := w.conn.SyscallConn()
		if err != nil {
			return w.flushFallback()
		}
		// Capture the FD into the platform struct; no closure escape after this.
		rawConn.Control(func(fd uintptr) { //nolint:errcheck
			w.platform.fd = fd
		})
		w.platform.fdReady = true
	}

	// Build the mmsghdr array for sendmmsg using pre-allocated slices.
	// No make() calls — all arrays are embedded in w.platform.
	mmsghdrs := w.platform.mmsghdrs[:n]
	iovecs := w.platform.iovecs[:n]
	sockaddrs := w.platform.sockaddrs[:n]

	for i, msg := range w.msgs {
		ip4 := msg.addr.IP.To4()
		if ip4 == nil {
			return w.flushFallback()
		}
		sockaddrs[i].Family = unix.AF_INET
		sockaddrs[i].Port = uint16(msg.addr.Port>>8) | uint16(msg.addr.Port<<8)
		copy(sockaddrs[i].Addr[:], ip4)

		iovecs[i].Base = &msg.buf[0]
		iovecs[i].SetLen(len(msg.buf))

		mmsghdrs[i].Hdr.Name = (*byte)(unsafe.Pointer(&sockaddrs[i]))
		mmsghdrs[i].Hdr.Namelen = uint32(unix.SizeofSockaddrInet4)
		mmsghdrs[i].Hdr.Iov = &iovecs[i]
		mmsghdrs[i].Hdr.Iovlen = 1
	}

	// Call sendmmsg directly using the cached FD — zero allocations.
	// This avoids rawConn.Control(closure) which would allocate a heap closure.
	// The FD stays valid as long as w.conn is alive (we hold a reference to it).
	sent := 0
	for sent < n {
		r, _, errno := unix.Syscall6(
			unix.SYS_SENDMMSG,
			w.platform.fd,
			uintptr(unsafe.Pointer(&mmsghdrs[sent])),
			uintptr(n-sent),
			0, 0, 0,
		)
		if errno != 0 {
			return errno
		}
		sent += int(r)
	}
	return nil
}

// flushFallback is used when sendmmsg cannot be used (e.g., IPv6 addresses).
func (w *batchWriter) flushFallback() error {
	var firstErr error
	for _, msg := range w.msgs {
		_, err := w.conn.WriteToUDP(msg.buf, msg.addr)
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// mmsghdr matches the Linux mmsghdr struct for sendmmsg/recvmmsg.
type mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
}

// readPlatform reads multiple packets using recvmmsg(2) — one syscall
// for up to N packets instead of N individual ReadFromUDP calls.
// All intermediate buffers and results are read from/into r.platform,
// eliminating the per-call make() heap allocations from the original code.
//
// Callers MUST NOT retain the returned []batchResult slice or any
// batchResult.addr pointer across the next Read() call — the backing
// storage is reused on every invocation.
func (r *batchReader) readPlatform() ([]batchResult, int, error) {
	n := len(r.bufs)
	if n == 0 {
		n = 1
	}

	// For single-packet reads, use regular ReadFromUDP (simpler, same perf).
	if n == 1 {
		nn, addr, err := r.conn.ReadFromUDP(r.bufs[0])
		if err != nil {
			return nil, 0, err
		}
		return []batchResult{{n: nn, addr: addr, buf: r.bufs[0][:nn]}}, 1, nil
	}

	// Cache rawConn on first read — SyscallConn() allocates a *rawConn each call,
	// so we call it once and store the interface value in the platform struct.
	if !r.platform.rcReady {
		rawConn, err := r.conn.SyscallConn()
		if err != nil {
			// Fallback to single read.
			nn, addr, err := r.conn.ReadFromUDP(r.bufs[0])
			if err != nil {
				return nil, 0, err
			}
			return []batchResult{{n: nn, addr: addr, buf: r.bufs[0][:nn]}}, 1, nil
		}
		r.platform.rawConn = rawConn
		r.platform.rcReady = true
	}

	// Build recvmmsg arrays using pre-allocated slices — zero make() calls.
	mmsghdrs := r.platform.mmsghdrs[:n]
	iovecs := r.platform.iovecs[:n]
	sockaddrs := r.platform.sockaddrs[:n]

	for i := range mmsghdrs {
		iovecs[i].Base = &r.bufs[i][0]
		iovecs[i].SetLen(len(r.bufs[i]))

		mmsghdrs[i].Hdr.Name = (*byte)(unsafe.Pointer(&sockaddrs[i]))
		mmsghdrs[i].Hdr.Namelen = uint32(unix.SizeofSockaddrInet4)
		mmsghdrs[i].Hdr.Iov = &iovecs[i]
		mmsghdrs[i].Hdr.Iovlen = 1
	}

	var count int
	var recvErr error
	// Use Read (blocking) to wait for at least one packet, then recvmmsg
	// picks up any additional packets that arrived.
	err := r.platform.rawConn.Read(func(fd uintptr) bool {
		rv, _, errno := unix.Syscall6(
			unix.SYS_RECVMMSG,
			fd,
			uintptr(unsafe.Pointer(&mmsghdrs[0])),
			uintptr(n),
			unix.MSG_DONTWAIT, // non-blocking after first wakeup
			0, 0,
		)
		if errno != 0 {
			if errno == unix.EAGAIN || errno == unix.EWOULDBLOCK {
				return false // tell rawConn to retry (wait for readability)
			}
			recvErr = errno
			return true
		}
		count = int(rv)
		return true
	})
	if err != nil {
		return nil, 0, err
	}
	if recvErr != nil {
		return nil, 0, recvErr
	}

	// Decode results using pre-allocated storage — no make() or net.IPv4() allocations.
	// r.platform.resultIPs[i] is a [16]byte array; we write the IPv4-mapped IPv6
	// representation directly (same layout as net.IPv4()) and alias it as net.IP.
	results := r.platform.results[:count]
	for i := 0; i < count; i++ {
		sa := &sockaddrs[i]
		port := int(sa.Port>>8) | int(sa.Port<<8)&0xFF00

		// Fill IPv4-in-IPv6 form directly into pre-allocated [16]byte.
		// This is identical to the 16-byte slice returned by net.IPv4(),
		// avoiding the heap allocation that net.IPv4() would cause.
		ip := r.platform.resultIPs[i][:]
		ip[0] = 0; ip[1] = 0; ip[2] = 0; ip[3] = 0
		ip[4] = 0; ip[5] = 0; ip[6] = 0; ip[7] = 0
		ip[8] = 0; ip[9] = 0; ip[10] = 0xff; ip[11] = 0xff
		ip[12] = sa.Addr[0]; ip[13] = sa.Addr[1]
		ip[14] = sa.Addr[2]; ip[15] = sa.Addr[3]

		// Reuse pre-allocated UDPAddr — update fields in place.
		r.platform.resultAddrs[i].IP = ip
		r.platform.resultAddrs[i].Port = port
		r.platform.resultAddrs[i].Zone = ""

		results[i] = batchResult{
			n:    int(mmsghdrs[i].Len),
			addr: &r.platform.resultAddrs[i],
			buf:  r.bufs[i][:mmsghdrs[i].Len],
		}
	}
	return results, count, nil
}
