//go:build windows

// Package service implements Windows Service Control Manager (SCM) integration
// for the VPN server. It allows the server to run as a Windows service that
// starts automatically on boot and is managed via the Services console or
// sc.exe / PowerShell commands.
//
// Usage:
//
//	// Check if we are running as a Windows service.
//	isService, _ := service.IsWindowsService()
//	if isService {
//	    return service.RunAsService("CavadVPN", serverRunFunc, logger)
//	}
//	// Otherwise run interactively.
//	serverRunFunc(ctx)
package service

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	// DefaultServiceName is the default Windows service name used with SCM.
	DefaultServiceName = "CavadVPN"
	// DefaultDisplayName is the friendly name shown in the Services console.
	DefaultDisplayName = "Cavad VPN Server"
	// DefaultDescription is the service description shown in the Services console.
	DefaultDescription = "Custom VPN server with Noise_XX encryption and TLS traffic obfuscation"

	// stopTimeout is the maximum time to wait for the server goroutine to exit
	// after a Stop/Shutdown control request.
	stopTimeout = 30 * time.Second
)

// RunFunc is the function signature for running the VPN server.
// ctx is cancelled when the Windows SCM sends a Stop or Shutdown command.
// The function must return when ctx is done.
type RunFunc func(ctx context.Context) error

// vpnService implements svc.Handler, bridging the Windows SCM lifecycle to
// the VPN server's context-based shutdown.
type vpnService struct {
	run    RunFunc
	logger *slog.Logger
}

// Execute is called by the Windows SCM to start the service. It runs the VPN
// server and handles Stop/Shutdown control requests by cancelling the context.
//
// Implements svc.Handler.
func (v *vpnService) Execute(
	_ []string,
	r <-chan svc.ChangeRequest,
	status chan<- svc.Status,
) (ssec bool, errno uint32) {
	// Notify SCM: service is starting up.
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run server in background goroutine; capture its exit error.
	errCh := make(chan error, 1)
	go func() {
		errCh <- v.run(ctx)
	}()

	// Notify SCM: service is running and accepts Stop/Shutdown.
	status <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				v.logger.Info("service: stop requested by SCM")
				status <- svc.Status{State: svc.StopPending}
				cancel()
				// Wait for the server to exit gracefully.
				select {
				case <-errCh:
					// Server exited — clean shutdown.
				case <-time.After(stopTimeout):
					v.logger.Warn("service: server did not stop within timeout, forcing exit",
						"timeout", stopTimeout)
				}
				return false, 0

			case svc.Interrogate:
				// SCM is asking for current status — echo it back.
				status <- c.CurrentStatus

			default:
				v.logger.Warn("service: unexpected SCM control request", "cmd", c.Cmd)
			}

		case err := <-errCh:
			// Server exited on its own (error or clean shutdown without Stop signal).
			if err != nil {
				v.logger.Error("service: server exited with error", "err", err)
				// Return a non-zero Win32 exit code to signal abnormal termination.
				return false, 1
			}
			v.logger.Info("service: server exited cleanly")
			return false, 0
		}
	}
}

// RunAsService starts the VPN server under Windows SCM control.
// name is the service name as registered in the SCM (must match Install).
// The call blocks until the service is stopped.
func RunAsService(name string, run RunFunc, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	v := &vpnService{run: run, logger: logger}
	if err := svc.Run(name, v); err != nil {
		return fmt.Errorf("service: run %q: %w", name, err)
	}
	return nil
}

// IsWindowsService reports whether the current process is running as a
// Windows service (as opposed to an interactive console session).
func IsWindowsService() (bool, error) {
	return svc.IsWindowsService()
}

// Install registers the VPN server executable as a Windows service in the SCM.
// If exePath is empty, the path of the current executable is used.
// Requires administrator privileges.
func Install(name, displayName, description, exePath string) error {
	if exePath == "" {
		var err error
		exePath, err = os.Executable()
		if err != nil {
			return fmt.Errorf("service: get executable path: %w", err)
		}
		exePath, err = filepath.Abs(exePath)
		if err != nil {
			return fmt.Errorf("service: resolve executable path: %w", err)
		}
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service: connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.CreateService(name, exePath, mgr.Config{
		DisplayName: displayName,
		Description: description,
		StartType:   mgr.StartAutomatic,
	})
	if err != nil {
		return fmt.Errorf("service: create service %q: %w", name, err)
	}
	defer s.Close()

	return nil
}

// Remove unregisters the Windows service identified by name from the SCM.
// The service must be stopped before calling Remove.
// Requires administrator privileges.
func Remove(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service: connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("service: open service %q: %w", name, err)
	}
	defer s.Close()

	if err := s.Delete(); err != nil {
		return fmt.Errorf("service: delete service %q: %w", name, err)
	}
	return nil
}
