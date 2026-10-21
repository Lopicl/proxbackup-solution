// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procPowerCreateRequest = kernel32.NewProc("PowerCreateRequest")
	procPowerSetRequest    = kernel32.NewProc("PowerSetRequest")
	procPowerClearRequest  = kernel32.NewProc("PowerClearRequest")
)

const (
	powerRequestContextVersion      = 0
	powerRequestContextSimpleString = 0x1
	powerRequestSystemRequired      = 1
)

// reasonContext is REASON_CONTEXT with the simple-string member of its union,
// padded to the size of the union's larger detailed member.
type reasonContext struct {
	version uint32
	flags   uint32
	reason  *uint16
	_       [2]uint32
	_       uintptr
}

// keepAwake holds a power request that keeps Windows from going to sleep on
// idle until release is called. It is listed by "powercfg /requests" with
// reason. Sleep the user asks for (lid, power button, Start menu) still happens.
func keepAwake(reason string) (release func(), err error) {
	s, err := windows.UTF16PtrFromString(reason)
	if err != nil {
		return nil, err
	}
	rc := reasonContext{version: powerRequestContextVersion, flags: powerRequestContextSimpleString, reason: s}
	h, _, e := procPowerCreateRequest.Call(uintptr(unsafe.Pointer(&rc)))
	if windows.Handle(h) == windows.InvalidHandle {
		return nil, fmt.Errorf("PowerCreateRequest: %w", e)
	}
	if ok, _, e := procPowerSetRequest.Call(h, powerRequestSystemRequired); ok == 0 {
		windows.CloseHandle(windows.Handle(h))
		return nil, fmt.Errorf("PowerSetRequest: %w", e)
	}
	return func() {
		procPowerClearRequest.Call(h, powerRequestSystemRequired)
		windows.CloseHandle(windows.Handle(h))
	}, nil
}

var (
	procCreateWaitableTimerW = kernel32.NewProc("CreateWaitableTimerW")
	procSetWaitableTimer     = kernel32.NewProc("SetWaitableTimer")
	procCancelWaitableTimer  = kernel32.NewProc("CancelWaitableTimer")
	wakeTimer                windows.Handle // kept open: closing it cancels the timer
)

// setWakeTimer makes Windows wake from sleep or hibernation at t (zero t
// cancels). Only one wake time is armed at a time. Windows ignores it when
// "Allow wake timers" is off in the power plan, which it reports as
// ERROR_NOT_SUPPORTED.
func setWakeTimer(t time.Time) error {
	if wakeTimer == 0 {
		h, _, e := procCreateWaitableTimerW.Call(0, 1, 0) // manual reset, unnamed
		if h == 0 {
			return fmt.Errorf("CreateWaitableTimer: %w", e)
		}
		wakeTimer = windows.Handle(h)
	}
	if t.IsZero() {
		procCancelWaitableTimer.Call(uintptr(wakeTimer))
		return nil
	}
	// A positive due time is absolute, in FILETIME units (UTC).
	due := windows.NsecToFiletime(t.UnixNano())
	ok, _, e := procSetWaitableTimer.Call(uintptr(wakeTimer), uintptr(unsafe.Pointer(&due)), 0, 0, 0, 1)
	if ok == 0 {
		return fmt.Errorf("SetWaitableTimer: %w", e)
	}
	if e == windows.ERROR_NOT_SUPPORTED {
		return errNoWake
	}
	return nil
}
