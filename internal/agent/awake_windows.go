// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"fmt"
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
