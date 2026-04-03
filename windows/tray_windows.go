//go:build windows

package main

import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows API constants for shell notification and windows messages.
const (
	niifNone        = 0x00000000
	nimAdd          = 0x00000000
	nimModify       = 0x00000001
	nimDelete       = 0x00000002
	nifMessage      = 0x00000001
	nifIcon         = 0x00000002
	nifTip          = 0x00000004
	wmApp           = 0x8000
	wmTrayIcon      = wmApp + 1
	wmCommand       = 0x0111
	wmDestroy       = 0x0002
	wmRButtonUp     = 0x0205
	wmLButtonDblClk = 0x0203

	// Menu item IDs
	menuConnect    = 1001
	menuDisconnect = 1002
	menuQuit       = 1003

	// Window class name
	wndClassName = "CavadVPNTrayClass"
)

var (
	shell32          = windows.NewLazySystemDLL("shell32.dll")
	user32           = windows.NewLazySystemDLL("user32.dll")
	procShellNotify  = shell32.NewProc("Shell_NotifyIconW")
	procCreateMenu   = user32.NewProc("CreatePopupMenu")
	procAppendMenu   = user32.NewProc("AppendMenuW")
	procTrackPopup   = user32.NewProc("TrackPopupMenu")
	procDestroyMenu  = user32.NewProc("DestroyMenu")
	procLoadIcon     = user32.NewProc("LoadIconW")
	procPostMessage  = user32.NewProc("PostMessageW")
	procGetCursorPos = user32.NewProc("GetCursorPos")
	procSetForeground = user32.NewProc("SetForegroundWindow")
)

// NOTIFYICONDATA is the Win32 NOTIFYICONDATAW structure.
type NOTIFYICONDATA struct {
	CbSize           uint32
	HWnd             windows.HWND
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            windows.Handle
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     windows.Handle
}

// POINT holds x,y coordinates for cursor position.
type POINT struct {
	X, Y int32
}

// windowsTray implements TrayApp using Shell_NotifyIcon.
type windowsTray struct {
	mu        sync.Mutex
	callbacks TrayCallbacks
	hwnd      windows.HWND
	nid       NOTIFYICONDATA
	quit      chan struct{}
	state     ConnectionState
}

func newTrayApp(callbacks TrayCallbacks) TrayApp {
	return &windowsTray{
		callbacks: callbacks,
		quit:      make(chan struct{}),
	}
}

func (t *windowsTray) Run() error {
	// Register window class
	className, _ := syscall.UTF16PtrFromString(wndClassName)
	wc := windows.WNDCLASSEX{
		CbSize:    uint32(unsafe.Sizeof(windows.WNDCLASSEX{})),
		LpszClassName: className,
		LpfnWndProc:   syscall.NewCallback(t.wndProc),
		HInstance:     windows.Handle(windows.GetModuleHandle(nil)),
	}
	if _, err := windows.RegisterClassEx(&wc); err != nil {
		return fmt.Errorf("tray: RegisterClassEx: %w", err)
	}

	// Create a hidden window to receive messages
	hwnd, err := windows.CreateWindowEx(
		0,
		className,
		nil,
		0, 0, 0, 0, 0,
		windows.HWND_MESSAGE, 0,
		windows.Handle(windows.GetModuleHandle(nil)), nil,
	)
	if err != nil {
		return fmt.Errorf("tray: CreateWindowEx: %w", err)
	}
	t.hwnd = hwnd

	// Load default icon (IDI_APPLICATION = 32512)
	hIcon, _, _ := procLoadIcon.Call(0, 32512)

	// Set up NOTIFYICONDATA
	t.nid = NOTIFYICONDATA{
		CbSize:           uint32(unsafe.Sizeof(NOTIFYICONDATA{})),
		HWnd:             hwnd,
		UID:              1,
		UFlags:           nifMessage | nifIcon | nifTip,
		UCallbackMessage: wmTrayIcon,
		HIcon:            windows.Handle(hIcon),
	}
	copy(t.nid.SzTip[:], syscall.StringToUTF16("CavadVPN - Disconnected"))

	// Add tray icon
	procShellNotify.Call(nimAdd, uintptr(unsafe.Pointer(&t.nid)))

	// Message pump
	var msg windows.MSG
	for {
		select {
		case <-t.quit:
			// Remove tray icon before exiting
			procShellNotify.Call(nimDelete, uintptr(unsafe.Pointer(&t.nid)))
			windows.DestroyWindow(hwnd)
			return nil
		default:
		}

		if ok := windows.GetMessage(&msg, 0, 0, 0); ok != 0 {
			windows.TranslateMessage(&msg)
			windows.DispatchMessage(&msg)
		}
	}
}

func (t *windowsTray) wndProc(hwnd windows.HWND, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmTrayIcon:
		switch lParam {
		case wmRButtonUp, wmLButtonDblClk:
			t.showContextMenu(hwnd)
		}
	case wmCommand:
		switch wParam & 0xFFFF {
		case menuConnect:
			if t.callbacks.OnConnect != nil {
				go t.callbacks.OnConnect()
			}
		case menuDisconnect:
			if t.callbacks.OnDisconnect != nil {
				go t.callbacks.OnDisconnect()
			}
		case menuQuit:
			if t.callbacks.OnQuit != nil {
				go t.callbacks.OnQuit()
			}
			t.Quit()
		}
	case wmDestroy:
		windows.PostQuitMessage(0)
	}
	return windows.DefWindowProc(hwnd, msg, wParam, lParam)
}

func (t *windowsTray) showContextMenu(hwnd windows.HWND) {
	hMenu, _, _ := procCreateMenu.Call()
	if hMenu == 0 {
		return
	}
	defer procDestroyMenu.Call(hMenu)

	t.mu.Lock()
	state := t.state
	t.mu.Unlock()

	if state == StateConnected || state == StateConnecting {
		connectStr, _ := syscall.UTF16PtrFromString("Disconnect")
		procAppendMenu.Call(hMenu, 0, menuDisconnect, uintptr(unsafe.Pointer(connectStr)))
	} else {
		connectStr, _ := syscall.UTF16PtrFromString("Connect")
		procAppendMenu.Call(hMenu, 0, menuConnect, uintptr(unsafe.Pointer(connectStr)))
	}

	// Separator (MF_SEPARATOR = 0x800)
	procAppendMenu.Call(hMenu, 0x800, 0, 0)

	quitStr, _ := syscall.UTF16PtrFromString("Quit CavadVPN")
	procAppendMenu.Call(hMenu, 0, menuQuit, uintptr(unsafe.Pointer(quitStr)))

	// Get cursor position and show menu
	var pt POINT
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForeground.Call(uintptr(hwnd))

	// TPM_RIGHTBUTTON = 0x2, TPM_BOTTOMALIGN = 0x20
	procTrackPopup.Call(hMenu, 0x22, uintptr(pt.X), uintptr(pt.Y), 0, uintptr(hwnd), 0)
}

func (t *windowsTray) SetStatus(state ConnectionState, assignedIP string) {
	t.mu.Lock()
	t.state = state
	t.mu.Unlock()

	var tip string
	switch state {
	case StateConnected:
		if assignedIP != "" {
			tip = fmt.Sprintf("CavadVPN - Connected (%s)", assignedIP)
		} else {
			tip = "CavadVPN - Connected"
		}
	case StateConnecting:
		tip = "CavadVPN - Connecting..."
	case StateDisconnecting:
		tip = "CavadVPN - Disconnecting..."
	case StateError:
		tip = "CavadVPN - Error"
	default:
		tip = "CavadVPN - Disconnected"
	}

	if t.hwnd != 0 {
		copy(t.nid.SzTip[:], syscall.StringToUTF16(tip))
		t.nid.UFlags = nifMessage | nifIcon | nifTip
		procShellNotify.Call(nimModify, uintptr(unsafe.Pointer(&t.nid)))
	}
}

func (t *windowsTray) Quit() {
	select {
	case <-t.quit:
	default:
		close(t.quit)
	}
}
