package main

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestNewStateMachine(t *testing.T) {
	sm := NewStateMachine()
	if sm.State() != StateDisconnected {
		t.Errorf("initial state: got %v, want Disconnected", sm.State())
	}
}

func TestStateString(t *testing.T) {
	tests := []struct {
		state ConnectionState
		want  string
	}{
		{StateDisconnected, "Disconnected"},
		{StateConnecting, "Connecting"},
		{StateConnected, "Connected"},
		{StateDisconnecting, "Disconnecting"},
		{StateError, "Error"},
		{ConnectionState(99), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("State(%d).String(): got %s, want %s", tt.state, got, tt.want)
		}
	}
}

func TestStateMachineTransition(t *testing.T) {
	sm := NewStateMachine()

	events := []StateEvent{}
	sm.AddListener(func(ev StateEvent) {
		events = append(events, ev)
	})

	// Disconnected → Connecting
	sm.Transition(StateEvent{State: StateConnecting, ServerAddr: "1.2.3.4:443"})
	if sm.State() != StateConnecting {
		t.Errorf("state: got %v, want Connecting", sm.State())
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].ServerAddr != "1.2.3.4:443" {
		t.Errorf("event ServerAddr: got %s", events[0].ServerAddr)
	}

	// Connecting → Connected
	sm.Transition(StateEvent{State: StateConnected, AssignedIP: "10.8.0.2"})
	if sm.State() != StateConnected {
		t.Errorf("state: got %v, want Connected", sm.State())
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[1].AssignedIP != "10.8.0.2" {
		t.Errorf("event AssignedIP: got %s", events[1].AssignedIP)
	}
}

func TestStateMachineNoopSameState(t *testing.T) {
	sm := NewStateMachine()

	callCount := 0
	sm.AddListener(func(ev StateEvent) {
		callCount++
	})

	// Transitioning to same state should be a no-op
	sm.Transition(StateEvent{State: StateDisconnected})
	if callCount != 0 {
		t.Errorf("same-state transition should not fire listener, got %d calls", callCount)
	}

	sm.Transition(StateEvent{State: StateConnecting})
	if callCount != 1 {
		t.Errorf("expected 1 listener call, got %d", callCount)
	}

	// Same state again — no-op
	sm.Transition(StateEvent{State: StateConnecting})
	if callCount != 1 {
		t.Errorf("same-state transition should not fire listener, got %d calls", callCount)
	}
}

func TestStateMachineLastEvent(t *testing.T) {
	sm := NewStateMachine()

	// Initially zero value
	ev := sm.LastEvent()
	if ev.State != 0 {
		t.Errorf("initial LastEvent state: got %v", ev.State)
	}

	testErr := errors.New("test error")
	sm.Transition(StateEvent{State: StateError, Error: testErr})
	ev = sm.LastEvent()
	if ev.State != StateError {
		t.Errorf("LastEvent state: got %v, want StateError", ev.State)
	}
	if ev.Error != testErr {
		t.Errorf("LastEvent error: got %v, want %v", ev.Error, testErr)
	}
}

func TestStateMachineIsConnected(t *testing.T) {
	sm := NewStateMachine()

	if sm.IsConnected() {
		t.Error("should not be connected initially")
	}

	sm.Transition(StateEvent{State: StateConnected})
	if !sm.IsConnected() {
		t.Error("should be connected after transition")
	}

	sm.Transition(StateEvent{State: StateDisconnected})
	if sm.IsConnected() {
		t.Error("should not be connected after disconnect")
	}
}

func TestStateMachineCanConnect(t *testing.T) {
	tests := []struct {
		state ConnectionState
		want  bool
	}{
		{StateDisconnected, true},
		{StateError, true},
		{StateConnecting, false},
		{StateConnected, false},
		{StateDisconnecting, false},
	}

	for _, tt := range tests {
		sm := NewStateMachine()
		if tt.state != StateDisconnected {
			// Force state via transition from connected
			if tt.state == StateError {
				sm.Transition(StateEvent{State: StateError})
			} else if tt.state == StateConnecting {
				sm.Transition(StateEvent{State: StateConnecting})
			} else if tt.state == StateConnected {
				sm.Transition(StateEvent{State: StateConnected})
			} else if tt.state == StateDisconnecting {
				sm.Transition(StateEvent{State: StateDisconnecting})
			}
		}
		if got := sm.CanConnect(); got != tt.want {
			t.Errorf("CanConnect() in state %v: got %v, want %v", tt.state, got, tt.want)
		}
	}
}

func TestStateMachineCanDisconnect(t *testing.T) {
	tests := []struct {
		state ConnectionState
		want  bool
	}{
		{StateDisconnected, false},
		{StateError, false},
		{StateConnecting, true},
		{StateConnected, true},
		{StateDisconnecting, false},
	}

	for _, tt := range tests {
		sm := NewStateMachine()
		if tt.state != StateDisconnected {
			if tt.state == StateError {
				sm.Transition(StateEvent{State: StateError})
			} else if tt.state == StateConnecting {
				sm.Transition(StateEvent{State: StateConnecting})
			} else if tt.state == StateConnected {
				sm.Transition(StateEvent{State: StateConnected})
			} else if tt.state == StateDisconnecting {
				sm.Transition(StateEvent{State: StateDisconnecting})
			}
		}
		if got := sm.CanDisconnect(); got != tt.want {
			t.Errorf("CanDisconnect() in state %v: got %v, want %v", tt.state, got, tt.want)
		}
	}
}

func TestStateMachineMultipleListeners(t *testing.T) {
	sm := NewStateMachine()

	var mu sync.Mutex
	calls := make(map[int]int)

	for i := 0; i < 3; i++ {
		i := i
		sm.AddListener(func(ev StateEvent) {
			mu.Lock()
			calls[i]++
			mu.Unlock()
		})
	}

	sm.Transition(StateEvent{State: StateConnecting})
	sm.Transition(StateEvent{State: StateConnected})

	mu.Lock()
	defer mu.Unlock()
	for i := 0; i < 3; i++ {
		if calls[i] != 2 {
			t.Errorf("listener %d: expected 2 calls, got %d", i, calls[i])
		}
	}
}

func TestStateMachineThreadSafety(t *testing.T) {
	sm := NewStateMachine()
	var wg sync.WaitGroup

	// Run concurrent transitions
	states := []ConnectionState{
		StateConnecting, StateConnected, StateDisconnecting, StateDisconnected,
	}

	for _, s := range states {
		s := s
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				sm.Transition(StateEvent{State: s})
				_ = sm.State()
				_ = sm.IsConnected()
				_ = sm.CanConnect()
				_ = sm.CanDisconnect()
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("timeout: potential deadlock in concurrent state transitions")
	}
}

func TestStateMachineErrorState(t *testing.T) {
	sm := NewStateMachine()
	testErr := errors.New("connection refused")

	sm.Transition(StateEvent{State: StateConnecting})
	sm.Transition(StateEvent{State: StateError, Error: testErr})

	if sm.State() != StateError {
		t.Errorf("state: got %v, want StateError", sm.State())
	}

	// Can connect from error state
	if !sm.CanConnect() {
		t.Error("should be able to connect from error state")
	}

	// Recovery: error → connecting → connected
	sm.Transition(StateEvent{State: StateConnecting})
	sm.Transition(StateEvent{State: StateConnected, AssignedIP: "10.8.0.5"})

	if sm.State() != StateConnected {
		t.Errorf("state: got %v, want StateConnected", sm.State())
	}
	if sm.LastEvent().AssignedIP != "10.8.0.5" {
		t.Errorf("AssignedIP: got %s", sm.LastEvent().AssignedIP)
	}
}
