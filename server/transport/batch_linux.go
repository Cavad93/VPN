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
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

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

	// Build the mmsghdr array for sendmmsg.
	mmsghdrs := make([]mmsghdr, n)
	iovecs := make([]unix.Iovec, n)
	sockaddrs := make([]unix.RawSockaddrInet4, n)

	for i, msg := range w.msgs {
		// Build sockaddr_in for each destination.
		ip4 := msg.addr.IP.To4()
		if ip4 == nil {
			// Skip non-IPv4 addresses, fall back for this batch.
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

// mmsghdr matches the Linux mmsghdr struct for sendmmsg/recvmmsg.
type mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
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
		return []batchResult{{n: nn, addr: addr, buf: r.bufs[0][:nn]}}, 1, nil
	}

	rawConn, err := r.conn.SyscallConn()
	if err != nil {
		// Fallback to single read.
		nn, addr, err := r.conn.ReadFromUDP(r.bufs[0])
		if err != nil {
			return nil, 0, err
		}
		return []batchResult{{n: nn, addr: addr, buf: r.bufs[0][:nn]}}, 1, nil
	}

	mmsghdrs := make([]mmsghdr, n)
	iovecs := make([]unix.Iovec, n)
	sockaddrs := make([]unix.RawSockaddrInet4, n)

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
	err = rawConn.Read(func(fd uintptr) bool {
		r, _, errno := unix.Syscall6(
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
		count = int(r)
		return true
	})
	if err != nil {
		return nil, 0, err
	}
	if recvErr != nil {
		return nil, 0, recvErr
	}

	// Convert raw sockaddrs to net.UDPAddr.
	results := make([]batchResult, count)
	for i := 0; i < count; i++ {
		sa := &sockaddrs[i]
		port := int(sa.Port>>8) | int(sa.Port<<8)&0xFF00
		results[i] = batchResult{
			n:    int(mmsghdrs[i].Len),
			addr: &net.UDPAddr{IP: net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3]), Port: port},
			buf:  r.bufs[i][:mmsghdrs[i].Len],
		}
	}
	return results, count, nil
}
