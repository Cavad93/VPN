package transport

import (
	"context"
	"net"
)

// UDPListener wraps a reliable UDP Listener and returns net.Conn-compatible
// connections (UDPNetConn) so the VPN server can use UDP+BBR as a drop-in
// replacement for TCP.
type UDPListener struct {
	inner *Listener
}

// ListenUDP creates a UDP listener on the given address that returns
// net.Conn-compatible connections with BBR congestion control.
func ListenUDP(addr string) (*UDPListener, error) {
	ln, err := Listen(addr)
	if err != nil {
		return nil, err
	}
	return &UDPListener{inner: ln}, nil
}

// Accept waits for the next incoming UDP connection and returns it as net.Conn.
// The returned connection uses BBR congestion control, reliable delivery,
// and ordered packets — suitable for ObfsConn → Noise → Mux stack.
func (l *UDPListener) Accept(ctx context.Context) (*UDPNetConn, error) {
	conn, err := l.inner.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return NewUDPNetConn(conn), nil
}

// Addr returns the listener's local network address.
func (l *UDPListener) Addr() net.Addr {
	return l.inner.Addr()
}

// Close shuts down the listener and all active connections.
func (l *UDPListener) Close() {
	l.inner.Close()
}

// DialUDP creates a reliable UDP connection to addr and returns it as net.Conn.
// The connection uses BBR congestion control — suitable for the full
// ObfsConn → Noise → Mux stack.
func DialUDP(addr string) (*UDPNetConn, error) {
	conn, err := Dial(addr)
	if err != nil {
		return nil, err
	}
	return NewUDPNetConn(conn), nil
}
