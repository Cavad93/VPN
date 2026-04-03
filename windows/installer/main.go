// Command cavadvpn-setup is the CavadVPN Windows self-installer.
//
// Usage:
//
//	cavadvpn-setup.exe [--install] [--install-dir DIR] [--server-addr ADDR]
//	                   [--server-key HEX] [--service] [--silent]
//	cavadvpn-setup.exe --uninstall [--install-dir DIR] [--silent]
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	var (
		install    = flag.Bool("install", false, "Install CavadVPN (default action)")
		uninstall  = flag.Bool("uninstall", false, "Uninstall CavadVPN")
		installDir = flag.String("install-dir", "", "Installation directory (default: Program Files\\CavadVPN)")
		serverAddr = flag.String("server-addr", "127.0.0.1:443", "VPN server address written into the default config")
		serverKey  = flag.String("server-key", "", "Server public key hex written into the default config (optional)")
		service    = flag.Bool("service", false, "Register a Windows Service (CavadVPN)")
		silent     = flag.Bool("silent", false, "Suppress interactive prompts")
	)
	flag.Parse()

	// Default action is install.
	if !*install && !*uninstall {
		*install = true
	}

	dir := *installDir
	if dir == "" {
		dir = DefaultInstallDir()
	}

	opts := InstallOptions{
		InstallDir: dir,
		ServerAddr: *serverAddr,
		ServerKey:  *serverKey,
		InstallSvc: *service,
		Silent:     *silent,
		Uninstall:  *uninstall,
	}

	var err error
	if *uninstall {
		fmt.Println("CavadVPN Uninstaller")
		fmt.Printf("Removing installation from: %s\n", dir)
		err = RunUninstall(opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Uninstall failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("CavadVPN has been uninstalled successfully.")
	} else {
		fmt.Println("CavadVPN Installer")
		fmt.Printf("Installing to: %s\n", dir)
		err = RunInstall(opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Install failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("CavadVPN has been installed successfully.")
		fmt.Printf("Configuration file: %s/config.json\n", dir)
		if *service {
			fmt.Println("Windows Service 'CavadVPN' has been registered.")
		}
	}
}
