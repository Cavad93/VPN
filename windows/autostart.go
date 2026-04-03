package main

// AutoStart manages registering the application to run on user login.
type AutoStart interface {
	// Enable registers the application to auto-start on login.
	Enable(exePath string) error
	// Disable removes the application from the auto-start list.
	Disable() error
	// IsEnabled reports whether auto-start is currently registered.
	IsEnabled() (bool, error)
}

// NewAutoStart returns the platform-appropriate AutoStart implementation.
func NewAutoStart() AutoStart {
	return newAutoStart()
}
