//go:build windows

package main

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// ConfigureTun assigns the IP address from cidr to the Wintun adapter, enables
// the interface, and configures Windows IP routing so VPN clients can reach the
// internet through the host.
//
// cidr must be in the form "x.x.x.x/prefix" (e.g. "10.8.0.1/24").
// name is the adapter's FriendlyName as passed to OpenTun / wintun.CreateAdapter.
//
// Requires: administrator privileges (netsh and reg commands).
func ConfigureTun(name, cidr string) error {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("ConfigureTun: parse CIDR %q: %w", cidr, err)
	}

	// Wintun adapters take a moment to appear in the network stack after
	// CreateAdapter. Retry netsh up to 5 times with 500 ms backoff.
	mask := ipv4MaskString(ipNet.Mask)
	var netshErr error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			time.Sleep(500 * time.Millisecond)
		}
		// netsh interface ip set address name="<name>" static <ip> <mask>
		out, err2 := exec.Command(
			"netsh", "interface", "ip", "set", "address",
			"name="+name, "static", ip.String(), mask,
		).CombinedOutput()
		if err2 == nil {
			netshErr = nil
			break
		}
		netshErr = fmt.Errorf("netsh set address (attempt %d): %w\nOutput: %s", attempt+1, err2, out)
	}
	if netshErr != nil {
		return fmt.Errorf("ConfigureTun: %w", netshErr)
	}

	// Set MTU to match the VPN tunnel overhead budget.
	// VPN framing per packet: mux(7) + noise_len(2) + noise_tag(16) + obfs(5) = 30 bytes.
	// tunMTU = MaxPayloadSize(1460) - overhead(30) = 1430 ensures each inner IP
	// packet produces exactly one UDP datagram with no splitting (see tun_linux.go).
	exec.Command( //nolint:errcheck
		"netsh", "interface", "ipv4", "set", "subinterface",
		name, "mtu=1430", "store=active",
	).Run()

	// Enable IP routing in the registry (takes effect after reboot; the
	// install script also sets this, but we set it here for completeness).
	exec.Command( //nolint:errcheck
		"reg", "add",
		`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
		"/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "1", "/f",
	).Run()

	// Add a NAT rule via PowerShell NetNAT so VPN clients can reach the internet.
	// This is best-effort (requires Windows Server / Hyper-V role).
	subnet := ipNet.String()
	exec.Command( //nolint:errcheck
		"powershell", "-NonInteractive", "-Command",
		fmt.Sprintf(
			`if (-not (Get-NetNat -Name CavadVPN -ErrorAction SilentlyContinue)) {`+
				` New-NetNat -Name CavadVPN -InternalIPInterfaceAddressPrefix '%s' }`,
			subnet,
		),
	).Run()

	return nil
}

// ConfigureTun6 assigns an IPv6 address from cidr6 to the Wintun adapter and
// enables IPv6 forwarding on Windows.
//
// cidr6 must be in the form "xxxx::x/prefix" (e.g. "fc00::1/120").
// Requires: administrator privileges.
func ConfigureTun6(name, cidr6 string) error {
	ip6, _, err := net.ParseCIDR(cidr6)
	if err != nil {
		return fmt.Errorf("ConfigureTun6: parse CIDR %q: %w", cidr6, err)
	}
	if ip6.To4() != nil {
		return fmt.Errorf("ConfigureTun6: %q is an IPv4 address, not IPv6", cidr6)
	}

	// Derive prefix length from CIDR.
	_, ipNet6, _ := net.ParseCIDR(cidr6)
	ones, _ := ipNet6.Mask.Size()

	// netsh interface ipv6 add address name="<name>" address=<ip6>/<prefixlen>
	out, err := exec.Command(
		"netsh", "interface", "ipv6", "add", "address",
		"interface="+name,
		fmt.Sprintf("address=%s/%d", ip6.String(), ones),
	).CombinedOutput()
	if err != nil {
		// Exit code 1 with "duplicate" error means already configured — OK.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 &&
			containsIgnoreCase(string(out), "duplicate") {
			// Already configured — not an error.
		} else {
			return fmt.Errorf("ConfigureTun6: netsh ipv6 add address: %w\nOutput: %s", err, out)
		}
	}

	// Enable IPv6 forwarding in the registry (best-effort).
	exec.Command( //nolint:errcheck
		"reg", "add",
		`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`,
		"/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "1", "/f",
	).Run()

	return nil
}

// containsIgnoreCase reports whether s contains substr, case-insensitively.
func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) &&
		strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// ipv4MaskString converts a net.IPMask to dotted-decimal notation (e.g. "255.255.255.0").
func ipv4MaskString(mask net.IPMask) string {
	if len(mask) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
	}
	// IPv6-style 16-byte mask — extract the last 4 bytes.
	if len(mask) == 16 {
		return fmt.Sprintf("%d.%d.%d.%d", mask[12], mask[13], mask[14], mask[15])
	}
	return "255.255.255.0"
}
