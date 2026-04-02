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
)

// tunIfreq is the ifreq structure for TUNSETIFF ioctl.
type tunIfreq struct {
	name  [16]byte
	flags uint16
	_     [22]byte
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

	return &linuxTun{file: f}, nil
}

func (t *linuxTun) Read(p []byte) (int, error)  { return t.file.Read(p) }
func (t *linuxTun) Write(p []byte) (int, error) { return t.file.Write(p) }
func (t *linuxTun) Close() error                { return t.file.Close() }
