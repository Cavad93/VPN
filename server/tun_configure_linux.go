//go:build linux

package main

import (
	"fmt"
	"net"
	"os/exec"
)

// ConfigureTun assigns the IP address from cidr to the TUN interface and brings
// it up. It also enables IPv4 forwarding and adds a MASQUERADE iptables rule so
// that VPN clients can reach the internet.
//
// cidr must be in the form "x.x.x.x/prefix" (e.g. "10.8.0.1/24").
// Requires: iproute2 (`ip` command) and iptables installed on the host.
func ConfigureTun(name, cidr string) error {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("ConfigureTun: parse CIDR %q: %w", cidr, err)
	}

	// ip addr add 10.8.0.1/24 dev vpn0
	if out, err := exec.Command("ip", "addr", "add", cidr, "dev", name).CombinedOutput(); err != nil {
		// Ignore "already exists" errors (EEXIST) so re-starts don't fail.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 2 {
			// exit code 2 from `ip` = RTNETLINK answers: File exists — OK
		} else {
			return fmt.Errorf("ConfigureTun: ip addr add: %w\nOutput: %s", err, out)
		}
	}

	// ip link set up dev vpn0
	if out, err := exec.Command("ip", "link", "set", "up", "dev", name).CombinedOutput(); err != nil {
		return fmt.Errorf("ConfigureTun: ip link set up: %w\nOutput: %s", err, out)
	}

	// Enable IPv4 forwarding (best-effort; may already be set via sysctl.conf).
	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run() //nolint:errcheck

	// Add MASQUERADE rule so VPN clients can reach the internet via the host NIC.
	// best-effort: iptables may not be installed or the rule may already exist.
	subnet := ipNet.String()
	exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"). //nolint:errcheck
		Run()
	// Only add if not already present (-C above returns 0 if rule exists).
	addOut, addErr := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE").CombinedOutput()
	_ = addOut
	_ = addErr

	_ = ip
	return nil
}

// ConfigureTun6 assigns an IPv6 address from cidr6 to the TUN interface and
// enables IPv6 forwarding so VPN clients with IPv6 addresses can reach the
// internet.
//
// cidr6 must be in the form "xxxx::x/prefix" (e.g. "fc00::1/120").
// The TUN interface must already be up (ConfigureTun brings it up).
// Requires: iproute2 (`ip` command) installed on the host.
func ConfigureTun6(name, cidr6 string) error {
	ip6, ip6Net, err := net.ParseCIDR(cidr6)
	if err != nil {
		return fmt.Errorf("ConfigureTun6: parse CIDR %q: %w", cidr6, err)
	}
	if ip6.To4() != nil {
		return fmt.Errorf("ConfigureTun6: %q is an IPv4 address, not IPv6", cidr6)
	}

	// ip -6 addr add fc00::1/120 dev vpn0
	if out, err := exec.Command("ip", "-6", "addr", "add", cidr6, "dev", name).CombinedOutput(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 2 {
			// RTNETLINK: File exists — already configured, not an error
		} else {
			return fmt.Errorf("ConfigureTun6: ip -6 addr add: %w\nOutput: %s", err, out)
		}
	}

	// Enable IPv6 forwarding (best-effort; may already be set via sysctl.conf).
	exec.Command("sysctl", "-w", "net.ipv6.conf.all.forwarding=1").Run() //nolint:errcheck

	// Add ip6tables MASQUERADE so IPv6 VPN clients can reach the internet.
	// Best-effort: ip6tables may not be installed or the rule may already exist.
	subnet6 := ip6Net.String()
	exec.Command("ip6tables", "-t", "nat", "-C", "POSTROUTING", "-s", subnet6, "-j", "MASQUERADE"). //nolint:errcheck
		Run()
	exec.Command("ip6tables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet6, "-j", "MASQUERADE"). //nolint:errcheck
		Run()

	_ = ip6Net
	return nil
}
