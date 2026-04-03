package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
)

var logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

func main() {
	minimized := flag.Bool("minimized", false, "Start minimized in system tray")
	configPath := flag.String("config", "", "Path to config file (default: platform config dir)")
	verbose := flag.Bool("v", false, "Enable verbose logging")
	flag.Parse()

	if *verbose {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	_ = minimized

	if err := run(context.Background(), *configPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// run executes the VPN client application. configPath may be "" to use the default location.
func run(ctx context.Context, configPath string) error {
	// Resolve config file path
	cfgPath := configPath
	if cfgPath == "" {
		var err error
		cfgPath, err = ConfigFilePath()
		if err != nil {
			return fmt.Errorf("cannot determine config path: %w", err)
		}
	}

	// Load or create default config
	cfg, err := loadOrDefaultConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("load config %s: %w", cfgPath, err)
	}

	return runWithConfig(ctx, cfg)
}

// loadOrDefaultConfig loads the config from path, creating a default if it doesn't exist.
func loadOrDefaultConfig(cfgPath string) (*Config, error) {
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg2 := DefaultConfig()
			cfg = &cfg2
			if saveErr := SaveConfig(cfgPath, cfg); saveErr != nil {
				logger.Warn("could not save default config", "path", cfgPath, "err", saveErr)
			} else {
				logger.Info("created default config", "path", cfgPath)
			}
			return cfg, nil
		}
		return nil, err
	}
	return cfg, nil
}

// appState bundles all runtime state for the VPN application.
type appState struct {
	sm  *StateMachine
	ks  KillSwitch
	vc  *VPNClient
	cfg *Config
}

// newAppState creates and initialises application state from config.
func newAppState(cfg *Config) *appState {
	sm := NewStateMachine()

	var ks KillSwitch
	if cfg.KillSwitch {
		ks = NewKillSwitch()
	}

	if cfg.AutoStart {
		as := NewAutoStart()
		exePath, _ := os.Executable()
		if err := as.Enable(exePath); err != nil {
			logger.Warn("could not enable auto-start", "err", err)
		}
	}

	vc := NewVPNClient(cfg)

	return &appState{sm: sm, ks: ks, vc: vc, cfg: cfg}
}

// handleConnect is called when the user requests a VPN connection.
func (a *appState) handleConnect(ctx context.Context, tray TrayApp) {
	if !a.sm.CanConnect() {
		return
	}
	a.sm.Transition(StateEvent{State: StateConnecting, ServerAddr: a.cfg.ServerAddr})
	tray.SetStatus(StateConnecting, "")

	go func() {
		route, err := a.vc.Connect(ctx)
		if err != nil {
			logger.Error("connect failed", "err", err)
			a.sm.Transition(StateEvent{State: StateError, Error: err})
			tray.SetStatus(StateError, "")
			return
		}

		if a.ks != nil {
			serverHost, _, _ := net.SplitHostPort(a.cfg.ServerAddr)
			if err := a.ks.Start(serverHost); err != nil {
				logger.Warn("kill switch start failed", "err", err)
			}
		}

		a.sm.Transition(StateEvent{
			State:      StateConnected,
			AssignedIP: route.AssignedIP,
			ServerAddr: a.cfg.ServerAddr,
		})
		tray.SetStatus(StateConnected, route.AssignedIP)
		logger.Info("connected", "ip", route.AssignedIP, "gw", route.Gateway)
	}()
}

// handleDisconnect is called when the user requests disconnection.
func (a *appState) handleDisconnect(tray TrayApp) {
	if !a.sm.CanDisconnect() {
		return
	}
	a.sm.Transition(StateEvent{State: StateDisconnecting})
	tray.SetStatus(StateDisconnecting, "")

	go func() {
		if a.ks != nil && a.ks.IsActive() {
			if err := a.ks.Stop(); err != nil {
				logger.Warn("kill switch stop failed", "err", err)
			}
		}
		a.vc.Disconnect()
		a.sm.Transition(StateEvent{State: StateDisconnected})
		tray.SetStatus(StateDisconnected, "")
		logger.Info("disconnected")
	}()
}

// handleQuit is called when the user requests application exit.
func (a *appState) handleQuit() {
	logger.Info("quit requested")
	if a.sm.IsConnected() {
		if a.ks != nil && a.ks.IsActive() {
			_ = a.ks.Stop()
		}
		a.vc.Disconnect()
	}
}

// shutdown performs graceful cleanup when a signal or context cancel is received.
func (a *appState) shutdown(tray TrayApp) {
	if a.ks != nil && a.ks.IsActive() {
		_ = a.ks.Stop()
	}
	a.vc.Disconnect()
	tray.Quit()
}

// runWithConfig starts the VPN client with the given configuration.
// ctx cancellation causes graceful shutdown.
func runWithConfig(ctx context.Context, cfg *Config) error {
	app := newAppState(cfg)

	var tray TrayApp
	tray = NewTrayApp(TrayCallbacks{
		OnConnect:    func() { app.handleConnect(ctx, tray) },
		OnDisconnect: func() { app.handleDisconnect(tray) },
		OnQuit:       func() { app.handleQuit() },
	})

	// Handle OS signals and context cancellation for graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			logger.Info("signal received, shutting down")
		case <-ctx.Done():
			logger.Info("context cancelled, shutting down")
		}
		app.shutdown(tray)
	}()

	// Run the tray (blocks until Quit is called)
	return tray.Run()
}
