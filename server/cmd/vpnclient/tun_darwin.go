//go:build darwin

package main

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// macOS utun constants (from <sys/sys_domain.h>, <net/if_utun.h>).
const (
	afSystem      = 32
	sysprotoCtrl  = 2
	utunCtrlName  = "com.apple.net.utun_control"
	utunOptIfname = 2
	ctliocginfo   = 0xC0644E03 // _IOWR('N', 3, struct ctl_info)
	utunHdrLen    = 4
	afInet uint32 = 2
)

type ctlInfo struct {
	ctlID   uint32
	ctlName [96]byte
}

type sockaddrCtl struct {
	scLen      uint8
	scFamily   uint8
	ssSysaddr  uint16
	scID       uint32
	scUnit     uint32
	scReserved [5]uint32
}

// tunDevice represents an open macOS utun interface.
type tunDevice struct {
	fd   int
	name string
}

// openTun opens a utun device.  The kernel assigns the next free interface
// name (utun0, utun1, …).
func openTun() (*tunDevice, error) {
	fd, err := syscall.Socket(afSystem, syscall.SOCK_DGRAM, sysprotoCtrl)
	if err != nil {
		return nil, fmt.Errorf("utun socket: %w", err)
	}

	var info ctlInfo
	copy(info.ctlName[:], utunCtrlName)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(fd), ctliocginfo, uintptr(unsafe.Pointer(&info)))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("CTLIOCGINFO: %w", errno)
	}

	sa := sockaddrCtl{
		scLen:    uint8(unsafe.Sizeof(sockaddrCtl{})),
		scFamily: afSystem,
		scID:     info.ctlID,
		scUnit:   0, // let the kernel pick
	}
	_, _, errno = syscall.RawSyscall(syscall.SYS_CONNECT,
		uintptr(fd),
		uintptr(unsafe.Pointer(&sa)),
		uintptr(unsafe.Sizeof(sa)))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("utun connect: %w", errno)
	}

	nameBuf := make([]byte, 32)
	nameLen := uint32(len(nameBuf))
	_, _, errno = syscall.Syscall6(syscall.SYS_GETSOCKOPT,
		uintptr(fd), sysprotoCtrl, utunOptIfname,
		uintptr(unsafe.Pointer(&nameBuf[0])),
		uintptr(unsafe.Pointer(&nameLen)), 0)
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("getsockopt UTUN_OPT_IFNAME: %w", errno)
	}
	// Trim trailing nulls.
	for i, b := range nameBuf {
		if b == 0 {
			nameBuf = nameBuf[:i]
			break
		}
	}

	return &tunDevice{fd: fd, name: string(nameBuf)}, nil
}

// Name returns the kernel-assigned interface name (e.g. "utun3").
func (t *tunDevice) Name() string { return t.name }

// Read reads one raw IPv4 packet, stripping the 4-byte utun AF header.
func (t *tunDevice) Read(buf []byte) (int, error) {
	tmp := make([]byte, len(buf)+utunHdrLen)
	n, err := syscall.Read(t.fd, tmp)
	if err != nil {
		return 0, &net.OpError{Op: "read", Net: "tun", Err: err}
	}
	if n <= utunHdrLen {
		return 0, nil
	}
	payload := n - utunHdrLen
	copy(buf, tmp[utunHdrLen:n])
	return payload, nil
}

// Write writes a raw IPv4 packet, prepending the 4-byte AF_INET utun header.
func (t *tunDevice) Write(pkt []byte) (int, error) {
	frame := make([]byte, utunHdrLen+len(pkt))
	// AF_INET = 2, big-endian 4 bytes: 0x00 0x00 0x00 0x02
	frame[3] = byte(afInet)
	copy(frame[utunHdrLen:], pkt)
	if _, err := syscall.Write(t.fd, frame); err != nil {
		return 0, &net.OpError{Op: "write", Net: "tun", Err: err}
	}
	return len(pkt), nil
}

// Close closes the file descriptor, which removes the utun interface.
func (t *tunDevice) Close() error { return syscall.Close(t.fd) }
