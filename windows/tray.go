package main

// TrayApp manages the system tray icon and associated UI.
type TrayApp interface {
	// Run starts the tray event loop (blocks until Quit is called).
	Run() error
	// SetStatus updates the tooltip/icon based on connection state.
	SetStatus(state ConnectionState, assignedIP string)
	// Quit signals the tray loop to exit.
	Quit()
}

// TrayCallbacks holds user-supplied handlers for tray menu actions.
type TrayCallbacks struct {
	OnConnect    func()
	OnDisconnect func()
	OnQuit       func()
}

// NewTrayApp returns the platform-appropriate TrayApp implementation.
func NewTrayApp(callbacks TrayCallbacks) TrayApp {
	return newTrayApp(callbacks)
}
