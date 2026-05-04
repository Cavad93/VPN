//go:build linux

// Package transport — batch_linux.go provides Linux-optimized batch I/O
// using sendmmsg(2) and recvmmsg(2) syscalls via golang.org/x/sys/unix.
//
// sendmmsg sends multiple UDP datagrams in a single syscall, reducing
// context switches from N to 1 per batch. This is the key optimization
// for user-space congestion control where per-packet syscall overhead
// is the primary bottleneck.
//
// Zero-allocation send path (steady-state):
//
//  1. mmsghdr/iovec/sockaddr arrays are embedded as VALUE fields in
//     batchWriterPlatform, which lives inside batchWriter. They are
//     allocated once with the connection — no per-flush make() or Pool.Get.
//
//  2. The socket FD is cached on the very first flush via a single
//     rawConn.Control() call. Subsequent flushes call unix.Syscall6(SYS_SENDMMSG)
//     directly, bypassing SyscallConn() (1 alloc/flush) and rawConn.Control's
//     closure (1 alloc/flush).
//
// Zero-allocation receive path (steady-state):
//
//  1. Same mmsghdr/iovec/sockaddr pre-allocation via batchReaderPlatform.
//
//  2. rawConn is cached after the first read — eliminates the SyscallConn()
//     allocation on every Read() call.
//
//  3. Results are written into r.resBuf (defined in batch.go) — no make() per batch.
//
//  4. udpAddrKeyFromRawIPv4 constructs the map key from raw sockaddr bytes without
//     allocating net.IP or *net.UDPAddr.
package transport

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// mmsghdr matches the Linux mmsghdr struct for sendmmsg/recvmmsg.
type mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
}

// batchWriterPlatform embeds pre-allocated send-side arrays for sendmmsg and
// a cached file descriptor so that flushPlatform can call SYS_SENDMMSG directly
// without allocating a rawConn wrapper or a closure on every flush.
//
// Memory: VALUE arrays — embedded in batchWriter, zero extra heap allocation.
type batchWriterPlatform struct {
	mmsghdrs  [maxBatchSize]mmsghdr
	iovecs    [maxBatchSize]unix.Iovec
	sockaddrs [maxBatchSize]unix.RawSockaddrInet4

	// fd is the cached socket file descriptor, set on the first flush.
	// After that, all flushes call SYS_SENDMMSG directly (no SyscallConn, no closure).
	fd      uintptr
	fdReady bool
}

// batchReaderPlatform embeds pre-allocated receive-side arrays for recvmmsg and
// a cached rawConn to avoid calling SyscallConn() on every Read() call.
//
// Memory: VALUE arrays — embedded in batchReader, zero extra heap allocation.
type batchReaderPlatform struct {
	mmsghdrs  [maxBatchSize]mmsghdr
	iovecs    [maxBatchSize]unix.Iovec
	sockaddrs [maxBatchSize]unix.RawSockaddrInet4

	// rawConn is cached after the first read — SyscallConn() allocates a new
	// *rawConn each call; caching it saves 1 alloc per Read().
	rawConn syscall.RawConn
	rcReady bool
}

// flushPlatform sends all queued packets using sendmmsg(2) — one syscall
// for up to 64 packets instead of 64 individual WriteToUDP calls.
//
// Steady-state allocations: 0.
//   - mmsghdr/iovec/sockaddr arrays read from w.platform (embedded VALUE fields).
//   - Cached FD used for direct SYS_SENDMMSG syscall — no SyscallConn(), no closure.
//
// First call only: one rawConn.Control() to cache the FD (one-time cost).
func (w *batchWriter) flushPlatform() error {
	n := len(w.msgs)
	if n == 0 {
		return nil
	}

	// Fast path: single packet — regular WriteToUDP (no mmsghdr overhead).
	if n == 1 {
		_, err := w.conn.WriteToUDP(w.msgs[0].buf, w.msgs[0].addr)
		return err
	}

	// One-time FD initialisation on the very first flush.
	// rawConn.Control() and its closure allocate here, but this path is taken
	// exactly once per batchWriter — it is not on the steady-state hot path.
	if !w.platform.fdReady {
		rawConn, err := w.conn.SyscallConn()
		if err != nil {
			return w.flushFallback()
		}
		rawConn.Control(func(fd uintptr) { //nolint:errcheck
			w.platform.fd = fd
		})
		w.platform.fdReady = true
	}

	// Build sendmmsg arguments using pre-allocated VALUE arrays — zero make() calls.
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

	// Direct sendmmsg via cached FD — no closure, no SyscallConn, zero allocations.
	// Safe: w.conn holds a reference to the FD, preventing GC finalization.
	// sendMu serializes all flushPlatform calls, so there is no concurrent access.
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

// readPlatform reads multiple packets using recvmmsg(2) — one syscall
// for up to N packets instead of N individual ReadFromUDP calls.
//
// Steady-state allocations: 1 (rawConn.Read closure — unavoidable with Go's API).
// Previous pool-based approach: 3 make() per call + pool Get/Put + SyscallConn().
// Now: 0 make() + no pool + 1 (cached rawConn, no SyscallConn after first read).
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
		r.resBuf[0] = batchResult{n: nn, key: makeUDPAddrKey(addr), buf: r.bufs[0][:nn]}
		return r.resBuf[:1], 1, nil
	}

	// Cache rawConn on first read — SyscallConn() allocates a new *rawConn each call.
	if !r.platform.rcReady {
		rawConn, err := r.conn.SyscallConn()
		if err != nil {
			nn, addr, err := r.conn.ReadFromUDP(r.bufs[0])
			if err != nil {
				return nil, 0, err
			}
			r.resBuf[0] = batchResult{n: nn, key: makeUDPAddrKey(addr), buf: r.bufs[0][:nn]}
			return r.resBuf[:1], 1, nil
		}
		r.platform.rawConn = rawConn
		r.platform.rcReady = true
	}

	// Build recvmmsg arguments using pre-allocated VALUE arrays — zero make() calls.
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
	// rawConn.Read blocks until the closure returns — closures are unavoidable
	// with the Go net API for blocking reads. We still save SyscallConn() and
	// make() allocations vs the previous implementation.
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

	// Write results into r.resBuf (pre-allocated in batchReader).
	// udpAddrKeyFromRawIPv4 constructs the map key from raw sockaddr bytes
	// without allocating a net.IP slice or *net.UDPAddr.
	res := r.resBuf[:count]
	for i := 0; i < count; i++ {
		sa := &sockaddrs[i]
		port := int(sa.Port>>8) | int(sa.Port<<8)&0xFF00
		res[i] = batchResult{
			n:   int(mmsghdrs[i].Len),
			key: udpAddrKeyFromRawIPv4(sa, port),
			buf: r.bufs[i][:mmsghdrs[i].Len],
		}
	}

	if err != nil {
		return nil, 0, err
	}
	if recvErr != nil {
		return nil, 0, recvErr
	}
	return res, count, nil
}

// udpAddrKeyFromRawIPv4 builds a udpAddrKey directly from a RawSockaddrInet4
// without allocating — eliminates net.IPv4() + &net.UDPAddr{} per received packet.
//
// Port byte-swap: recvmmsg stores ports in network byte order (big-endian),
// so we swap to host order: host_port = (sa.Port>>8) | ((sa.Port&0xFF)<<8).
// This is identical to the byte-swap used by net.UDPAddr for kernel sockaddrs.
func udpAddrKeyFromRawIPv4(sa *unix.RawSockaddrInet4, hostPort int) udpAddrKey {
	var k udpAddrKey
	// Normalise to IPv4-in-IPv6 form to match makeUDPAddrKey(net.UDPAddr{IP:net.IPv4(...)}).
	k.ip[10] = 0xff
	k.ip[11] = 0xff
	copy(k.ip[12:], sa.Addr[:])
	k.port = hostPort
	// k.zone = "" (zero value) — IPv4 has no link-local zone.
	return k
}
