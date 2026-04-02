//go:build linux

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	tunDevice = "/dev/net/tun"
	iffTun    = 0x0001
	iffNoPi   = 0x1000

	// tunMTU is the MTU configured on the TUN interface.
	// VPN framing overhead per packet:
	//   mux header:   7 bytes
	//   noise header: 2 + 16 (AEAD tag) = 18 bytes
	//   obfs header:  5 bytes
	//   total:        30 bytes
	// Setting MTU = 1500 - 30 - 50 (safety margin) = 1420 ensures that inner
	// IP packets, after VPN wrapping, stay within the 1500-byte Ethernet MTU
	// of the physical interface and are never fragmented.
	tunMTU = 1420
)

// tunIfreq is the ifreq structure for TUNSETIFF ioctl.
type tunIfreq struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}

// tunIfreqMTU is the ifreq structure for SIOCSIFMTU ioctl.
// The MTU field overlaps with the flags field in the union.
type tunIfreqMTU struct {
	name [16]byte
	mtu  int32
	_    [18]byte
}

// linuxTun implements TunDevice using Linux's /dev/net/tun.
type linuxTun struct {
	file *os.File
}

// OpenTun opens (or creates) a TUN device with the given name.
func OpenTun(name string) (TunDevice, error) {
	f, err := os.OpenFile(tunDevice, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("OpenTun: open %s: %w", tunDevice, err)
	}

	var ifr tunIfreq
	if len(name) >= len(ifr.name) {
		f.Close()
		return nil, fmt.Errorf("OpenTun: interface name %q too long", name)
	}
	copy(ifr.name[:], name)
	ifr.flags = iffTun | iffNoPi

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		syscall.TUNSETIFF,
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		f.Close()
		return nil, fmt.Errorf("OpenTun: TUNSETIFF ioctl: %w", errno)
	}

	// Set MTU via SIOCSIFMTU on a temporary UDP socket (standard approach).
	// We need a real network socket, not the TUN fd, for SIOCSIFMTU.
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err == nil {
		var mtuReq tunIfreqMTU
		copy(mtuReq.name[:], name)
		mtuReq.mtu = tunMTU
		syscall.Syscall( //nolint:errcheck — best-effort; kernel uses 1500 if this fails
			syscall.SYS_IOCTL,
			uintptr(sock),
			syscall.SIOCSIFMTU,
			uintptr(unsafe.Pointer(&mtuReq)),
		)
		syscall.Close(sock)
	}

	return &linuxTun{file: f}, nil
}

func (t *linuxTun) Read(p []byte) (int, error)  { return t.file.Read(p) }
func (t *linuxTun) Write(p []byte) (int, error) { return t.file.Write(p) }
func (t *linuxTun) Close() error                { return t.file.Close() }
