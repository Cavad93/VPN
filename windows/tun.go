package main

// TunDevice is the interface for reading/writing raw IP packets to/from a TUN device.
type TunDevice interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

// TunConfig holds parameters for configuring a TUN interface.
type TunConfig struct {
	Name      string
	LocalIP   string
	GatewayIP string
	PrefixLen int
	MTU       int
}

// OpenTun creates or opens a TUN device with the given configuration.
// Returns ErrNotWindows on non-Windows platforms.
func OpenTun(cfg TunConfig) (TunDevice, error) {
	return openTun(cfg)
}
