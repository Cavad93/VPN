//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"sync"
)

const (
	ruleBlockAll    = "CavadVPN-Block-All"
	ruleAllowServer = "CavadVPN-Allow-Server"
	ruleAllowLocal  = "CavadVPN-Allow-Local"
	ruleAllowDHCP   = "CavadVPN-Allow-DHCP"
)

// windowsKillSwitch implements KillSwitch using Windows netsh advfirewall.
type windowsKillSwitch struct {
	mu       sync.Mutex
	active   bool
	serverIP string
}

func newKillSwitch() KillSwitch {
	return &windowsKillSwitch{}
}

func (ks *windowsKillSwitch) Start(serverIP string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.active {
		// Update server IP if it changed
		if ks.serverIP != serverIP {
			if err := ks.removeRule(ruleAllowServer); err != nil {
				return err
			}
			if err := ks.addAllowServerRule(serverIP); err != nil {
				return err
			}
			ks.serverIP = serverIP
		}
		return nil
	}

	// Block all outbound traffic
	if err := netsh("advfirewall", "firewall", "add", "rule",
		"name="+ruleBlockAll,
		"protocol=any", "dir=out", "action=block"); err != nil {
		return fmt.Errorf("killswitch: add block-all rule: %w", err)
	}

	// Allow traffic to VPN server
	if err := ks.addAllowServerRule(serverIP); err != nil {
		_ = ks.removeRule(ruleBlockAll)
		return err
	}

	// Allow loopback traffic
	if err := netsh("advfirewall", "firewall", "add", "rule",
		"name="+ruleAllowLocal,
		"protocol=any", "dir=out",
		"remoteip=127.0.0.1-127.255.255.255",
		"action=allow"); err != nil {
		_ = ks.removeRule(ruleBlockAll)
		_ = ks.removeRule(ruleAllowServer)
		return fmt.Errorf("killswitch: add allow-local rule: %w", err)
	}

	// Allow DHCP
	if err := netsh("advfirewall", "firewall", "add", "rule",
		"name="+ruleAllowDHCP,
		"protocol=UDP", "dir=out",
		"localport=68", "remoteport=67",
		"action=allow"); err != nil {
		_ = ks.removeRule(ruleBlockAll)
		_ = ks.removeRule(ruleAllowServer)
		_ = ks.removeRule(ruleAllowLocal)
		return fmt.Errorf("killswitch: add allow-dhcp rule: %w", err)
	}

	ks.active = true
	ks.serverIP = serverIP
	return nil
}

func (ks *windowsKillSwitch) Stop() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if !ks.active {
		return nil
	}

	var errs []error
	for _, rule := range []string{ruleBlockAll, ruleAllowServer, ruleAllowLocal, ruleAllowDHCP} {
		if err := ks.removeRule(rule); err != nil {
			errs = append(errs, err)
		}
	}

	ks.active = false
	ks.serverIP = ""

	if len(errs) > 0 {
		return fmt.Errorf("killswitch: stop errors: %v", errs)
	}
	return nil
}

func (ks *windowsKillSwitch) IsActive() bool {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	return ks.active
}

func (ks *windowsKillSwitch) addAllowServerRule(serverIP string) error {
	return netsh("advfirewall", "firewall", "add", "rule",
		"name="+ruleAllowServer,
		"protocol=TCP", "dir=out",
		"remoteip="+serverIP,
		"action=allow")
}

func (ks *windowsKillSwitch) removeRule(name string) error {
	return netsh("advfirewall", "firewall", "delete", "rule", "name="+name)
}

func netsh(args ...string) error {
	out, err := exec.Command("netsh", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %v: %s: %w", args, out, err)
	}
	return nil
}
