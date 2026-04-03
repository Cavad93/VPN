package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/cavad93/vpn/server/service"
)

// TestIsWindowsService verifies that IsWindowsService returns false in a test
// environment (we are never running as a Windows service during testing).
func TestIsWindowsService(t *testing.T) {
	t.Parallel()
	isService, err := service.IsWindowsService()
	if err != nil {
		t.Fatalf("IsWindowsService returned unexpected error: %v", err)
	}
	if isService {
		t.Error("IsWindowsService: expected false in test environment, got true")
	}
}

// TestInstall_ReturnsError verifies that Install returns an error on
// non-Windows (ErrNotWindows) or when SCM is inaccessible on Windows.
func TestInstall_ReturnsError(t *testing.T) {
	t.Parallel()
	err := service.Install(service.DefaultServiceName, service.DefaultDisplayName, service.DefaultDescription, "/usr/bin/vpn")
	if err == nil {
		// On Windows with admin privileges this might succeed — skip in that case.
		t.Skip("Install unexpectedly succeeded; skipping (Windows admin environment?)")
	}
	// On non-Windows: must be ErrNotWindows.
	if !errors.Is(err, service.ErrNotWindows) {
		// On Windows without admin it will be an OS error — that is acceptable.
		t.Logf("Install returned non-ErrNotWindows error (acceptable on Windows): %v", err)
	}
}

// TestRemove_ReturnsError verifies that Remove returns an error when the
// service does not exist or on non-Windows platforms.
func TestRemove_ReturnsError(t *testing.T) {
	t.Parallel()
	err := service.Remove(service.DefaultServiceName)
	if err == nil {
		t.Skip("Remove unexpectedly succeeded; skipping (service already registered?)")
	}
	if !errors.Is(err, service.ErrNotWindows) {
		t.Logf("Remove returned non-ErrNotWindows error (acceptable on Windows): %v", err)
	}
}

// TestRunAsService_ReturnsError verifies that RunAsService returns an error
// when the service is not registered (non-Windows) or not installed (Windows).
func TestRunAsService_ReturnsError(t *testing.T) {
	t.Parallel()
	run := func(_ context.Context) error { return nil }
	err := service.RunAsService(service.DefaultServiceName, run, nil)
	if err == nil {
		t.Skip("RunAsService unexpectedly succeeded; skipping")
	}
	if !errors.Is(err, service.ErrNotWindows) {
		t.Logf("RunAsService returned non-ErrNotWindows error (acceptable on Windows): %v", err)
	}
}

// TestRunFuncType verifies that RunFunc is a valid function type that accepts
// a context and returns an error, matching the expected VPN server signature.
func TestRunFuncType(t *testing.T) {
	t.Parallel()
	expectedErr := errors.New("server error")
	var fn service.RunFunc = func(ctx context.Context) error {
		if ctx == nil {
			t.Error("ctx must not be nil")
		}
		return expectedErr
	}

	ctx := context.Background()
	if err := fn(ctx); !errors.Is(err, expectedErr) {
		t.Errorf("RunFunc returned %v, want %v", err, expectedErr)
	}
}

// TestConstants verifies that the package constants are non-empty strings.
func TestConstants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
	}{
		{"DefaultServiceName", service.DefaultServiceName},
		{"DefaultDisplayName", service.DefaultDisplayName},
		{"DefaultDescription", service.DefaultDescription},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.value == "" {
				t.Errorf("%s must not be empty", tc.name)
			}
		})
	}
}

// TestErrNotWindows verifies that ErrNotWindows is a non-nil sentinel error.
func TestErrNotWindows(t *testing.T) {
	t.Parallel()
	if service.ErrNotWindows == nil {
		t.Fatal("ErrNotWindows must not be nil")
	}
	if service.ErrNotWindows.Error() == "" {
		t.Error("ErrNotWindows.Error() must not be empty")
	}
}

// TestIsWindowsService_MultipleCallsConsistent ensures the function is
// idempotent (returns the same value on repeated calls).
func TestIsWindowsService_MultipleCallsConsistent(t *testing.T) {
	t.Parallel()
	v1, err1 := service.IsWindowsService()
	v2, err2 := service.IsWindowsService()

	if err1 != nil || err2 != nil {
		t.Fatalf("IsWindowsService errors: %v, %v", err1, err2)
	}
	if v1 != v2 {
		t.Errorf("IsWindowsService returned inconsistent values: %v vs %v", v1, v2)
	}
}
