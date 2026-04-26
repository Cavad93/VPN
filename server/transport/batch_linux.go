//go:build linux

// Package transport — batch_linux.go provides Linux-optimized batch I/O
// using sendmmsg(2) and recvmmsg(2) syscalls via golang.org/x/sys/unix.
//
// sendmmsg sends multiple UDP datagrams in a single syscall, reducing
// context switches from N to 1 per batch. This is the key optimization
// for user-space congestion control where per-packet syscall overhead
// is the primary bottleneck.
package transport

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// mmsghdr matches the Linux mmsghdr struct for sendmmsg/recvmmsg.
type mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
}

// mmsgState holds the fixed-size arrays required for sendmmsg/recvmmsg.
// Using a pooled struct eliminates three make() calls (~6 KB total) per
// batch flush/read call:
//
//   - [maxBatchSize]mmsghdr         ≈ 64 × 64 bytes = 4 096 bytes
//   - [maxBatchSize]unix.Iovec      ≈ 64 × 16 bytes = 1 024 bytes
//   - [maxBatchSize]RawSockaddrInet4 ≈ 64 × 16 bytes = 1 024 bytes
//   - total                                          = 6 144 bytes
//
// At 30 Mbps with batch size 16: ~164 batch ops/sec × 6 KB ≈ 1 MB/sec
// heap pressure → eliminated. The pool holds at most one item per goroutine
// (flush and read are each single-goroutine paths), so contention is zero.
type mmsgState struct {
	hdrs  [maxBatchSize]mmsghdr
	iovs  [maxBatchSize]unix.Iovec
	addrs [maxBatchSize]unix.RawSockaddrInet4
}

// mmsgStatePool pools mmsgState objects to avoid per-batch heap allocation.
// Safety: Control/Read run the closure synchronously (the goroutine blocks
// until the syscall completes), so the state is never in use when Put is called.
var mmsgStatePool = sync.Pool{New: func() any { return new(mmsgState) }}

// flushPlatform sends all queued packets using sendmmsg(2) — one syscall
// for up to 64 packets instead of 64 individual WriteToUDP calls.
func (w *batchWriter) flushPlatform() error {
	n := len(w.msgs)
	if n == 0 {
		return nil
	}

	// Fast path: single packet — use regular WriteToUDP (no syscall overhead
	// from building mmsghdr arrays).
	if n == 1 {
		_, err := w.conn.WriteToUDP(w.msgs[0].buf, w.msgs[0].addr)
		return err
	}

	// Get the raw socket FD.
	rawConn, err := w.conn.SyscallConn()
	if err != nil {
		return w.flushFallback()
	}

	// Borrow pre-allocated header arrays from the pool — zero heap allocation.
	state := mmsgStatePool.Get().(*mmsgState)
	mmsghdrs := state.hdrs[:n]
	iovecs := state.iovs[:n]
	sockaddrs := state.addrs[:n]

	for i, msg := range w.msgs {
		// Build sockaddr_in for each destination.
		ip4 := msg.addr.IP.To4()
		if ip4 == nil {
			// Return state before falling back to avoid a leak.
			mmsgStatePool.Put(state)
			return w.flushFallback()
		}
		sockaddrs[i].Family = unix.AF_INET
		// Port is big-endian in sockaddr_in.
		sockaddrs[i].Port = uint16(msg.addr.Port>>8) | uint16(msg.addr.Port<<8)
		copy(sockaddrs[i].Addr[:], ip4)

		// Build iovec pointing to packet data.
		iovecs[i].Base = &msg.buf[0]
		iovecs[i].SetLen(len(msg.buf))

		// Build mmsghdr.
		mmsghdrs[i].Hdr.Name = (*byte)(unsafe.Pointer(&sockaddrs[i]))
		mmsghdrs[i].Hdr.Namelen = uint32(unix.SizeofSockaddrInet4)
		mmsghdrs[i].Hdr.Iov = &iovecs[i]
		mmsghdrs[i].Hdr.Iovlen = 1
	}

	// Call sendmmsg via raw syscall.
	// rawConn.Control blocks until the closure returns — state is valid throughout.
	var sendErr error
	err = rawConn.Control(func(fd uintptr) {
		sent := 0
		for sent < n {
			r, _, errno := unix.Syscall6(
				unix.SYS_SENDMMSG,
				fd,
				uintptr(unsafe.Pointer(&mmsghdrs[sent])),
				uintptr(n-sent),
				0, // flags
				0, 0,
			)
			if errno != 0 {
				sendErr = errno
				return
			}
			sent += int(r)
		}
	})
	// Return state after Control completes — syscall is done, memory is safe to reuse.
	mmsgStatePool.Put(state)
	if err != nil {
		return err
	}
	return sendErr
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

	rawConn, err := r.conn.SyscallConn()
	if err != nil {
		// Fallback to single read.
		nn, addr, err := r.conn.ReadFromUDP(r.bufs[0])
		if err != nil {
			return nil, 0, err
		}
		r.resBuf[0] = batchResult{n: nn, key: makeUDPAddrKey(addr), buf: r.bufs[0][:nn]}
		return r.resBuf[:1], 1, nil
	}

	// Borrow pre-allocated header arrays from the pool — zero heap allocation.
	state := mmsgStatePool.Get().(*mmsgState)
	mmsghdrs := state.hdrs[:n]
	iovecs := state.iovs[:n]
	sockaddrs := state.addrs[:n]

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
	// rawConn.Read blocks until the closure returns — state is valid throughout.
	err = rawConn.Read(func(fd uintptr) bool {
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

	// Build results directly into r.resBuf — eliminates make([]batchResult, count).
	// udpAddrKeyFromRawIPv4 constructs the key from raw sockaddr bytes without
	// allocating a net.IP slice or *net.UDPAddr (~2 allocs eliminated per packet).
	// All data is value-copied out of state before it is returned to the pool.
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
	// Return state now: res contains no references into state arrays.
	mmsgStatePool.Put(state)

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
