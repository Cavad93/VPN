//go:build windows

package main

import (
	"fmt"
	"net"
	"os/exec"
)

// windowsTun implements TunDevice using netsh on Windows.
// Note: A real TUN on Windows requires the Wintun driver (wintun.dll).
// This implementation documents the setup steps and requires the driver to
// be pre-installed. For testing, use a mock implementation.
type windowsTun struct {
	name   string
	closed bool
	r      *net.IPConn
	w      *net.IPConn
}

func openTun(cfg TunConfig) (TunDevice, error) {
	// On Windows a real TUN requires the Wintun driver.
	// We configure the interface via netsh after it is created by Wintun.
	// Since Wintun integration requires the wintun.dll at runtime (not
	// compile time), we return an error that informs the user.
	return nil, fmt.Errorf("tun: Windows TUN requires the Wintun driver " +
		"(wintun.dll). Please install Wintun from https://www.wintun.net/ " +
		"and restart the application")
}

// configureTunInterface sets up IP address and routes using netsh.
// This is called externally after the Wintun device is open.
func configureTunInterface(ifaceName, localIP, gateway string, prefixLen, mtu int) error {
	// Set IP address on the interface.
	mask := net.CIDRMask(prefixLen, 32)
	netmask := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])

	out, err := exec.Command("netsh", "interface", "ip", "set", "address",
		"name="+ifaceName,
		"static", localIP, netmask, gateway).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tun: netsh set address: %s: %w", out, err)
	}

	// Set MTU.
	out, err = exec.Command("netsh", "interface", "ipv4", "set", "interface",
		ifaceName, fmt.Sprintf("mtu=%d", mtu)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tun: netsh set mtu: %s: %w", out, err)
	}

	return nil
}

// addDefaultRoute adds a default route through the VPN tunnel.
func addDefaultRoute(gateway, ifaceName string) error {
	out, err := exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0",
		gateway, "if", ifaceName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tun: route add default: %s: %w", out, err)
	}
	return nil
}

// deleteDefaultRoute removes a previously added default route.
func deleteDefaultRoute(gateway string) error {
	out, err := exec.Command("route", "delete", "0.0.0.0",
		"mask", "0.0.0.0", gateway).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tun: route delete default: %s: %w", out, err)
	}
	return nil
}
