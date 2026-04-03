package main

import (
	"sync"
)

// ConnectionState represents the current state of the VPN connection.
type ConnectionState int

const (
	StateDisconnected  ConnectionState = iota
	StateConnecting
	StateConnected
	StateDisconnecting
	StateError
)

// String returns a human-readable name for the state.
func (s ConnectionState) String() string {
	switch s {
	case StateDisconnected:
		return "Disconnected"
	case StateConnecting:
		return "Connecting"
	case StateConnected:
		return "Connected"
	case StateDisconnecting:
		return "Disconnecting"
	case StateError:
		return "Error"
	default:
		return "Unknown"
	}
}

// StateEvent carries state change information to registered listeners.
type StateEvent struct {
	State      ConnectionState
	AssignedIP string
	ServerAddr string
	Error      error
}

// StateListener is called when the connection state changes.
type StateListener func(StateEvent)

// StateMachine manages VPN connection state and notifies registered listeners.
type StateMachine struct {
	mu        sync.RWMutex
	state     ConnectionState
	listeners []StateListener
	lastEvent StateEvent
}

// NewStateMachine creates a new StateMachine in the Disconnected state.
func NewStateMachine() *StateMachine {
	return &StateMachine{
		state: StateDisconnected,
	}
}

// State returns the current connection state (thread-safe).
func (sm *StateMachine) State() ConnectionState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.state
}

// LastEvent returns the most recent StateEvent (thread-safe).
func (sm *StateMachine) LastEvent() StateEvent {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.lastEvent
}

// AddListener registers a callback to be invoked on state changes.
// The callback is called synchronously while the write lock is NOT held —
// callbacks must not call methods on the StateMachine to avoid deadlock.
func (sm *StateMachine) AddListener(l StateListener) {
	sm.mu.Lock()
	sm.listeners = append(sm.listeners, l)
	sm.mu.Unlock()
}

// Transition sets the state and fires all registered listeners.
// It is a no-op if the requested state equals the current state.
func (sm *StateMachine) Transition(ev StateEvent) {
	sm.mu.Lock()
	if sm.state == ev.State {
		sm.mu.Unlock()
		return
	}
	sm.state = ev.State
	sm.lastEvent = ev
	// Snapshot listeners so we can release the lock before calling them.
	listeners := make([]StateListener, len(sm.listeners))
	copy(listeners, sm.listeners)
	sm.mu.Unlock()

	for _, l := range listeners {
		l(ev)
	}
}

// IsConnected returns true if the current state is StateConnected.
func (sm *StateMachine) IsConnected() bool {
	return sm.State() == StateConnected
}

// CanConnect returns true if the VPN can be connected from the current state.
func (sm *StateMachine) CanConnect() bool {
	s := sm.State()
	return s == StateDisconnected || s == StateError
}

// CanDisconnect returns true if the VPN can be disconnected from the current state.
func (sm *StateMachine) CanDisconnect() bool {
	s := sm.State()
	return s == StateConnected || s == StateConnecting
}
