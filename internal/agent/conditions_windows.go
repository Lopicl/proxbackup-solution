// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procGetSystemPowerStatus = kernel32.NewProc("GetSystemPowerStatus")
	ole32                    = windows.NewLazySystemDLL("ole32.dll")
	procCoCreateInstance     = ole32.NewProc("CoCreateInstance")

	// Network List Manager (netlistmgr.h).
	clsidNetworkListManager = windows.GUID{Data1: 0xDCB00C01, Data2: 0x570F, Data3: 0x4A9B,
		Data4: [8]byte{0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B}}
	iidINetworkCostManager = windows.GUID{Data1: 0xDCB00008, Data2: 0x570F, Data3: 0x4A9B,
		Data4: [8]byte{0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B}}
)

// systemPowerStatus is SYSTEM_POWER_STATUS.
type systemPowerStatus struct {
	ACLineStatus        byte // 0 = offline (battery), 1 = online, 255 = unknown
	BatteryFlag         byte
	BatteryLifePercent  byte
	SystemStatusFlag    byte
	BatteryLifeTime     uint32
	BatteryFullLifeTime uint32
}

// NLM_CONNECTION_COST flags that make a connection metered.
const (
	nlmCostFixed         = 0x2     // a data plan with a fixed amount of data
	nlmCostVariable      = 0x4     // charged per byte
	nlmCostOverDataLimit = 0x10000 // over the plan's data limit
	nlmCostRoaming       = 0x40000
)

const clsctxAll = 0x17 // CLSCTX_INPROC_SERVER | INPROC_HANDLER | LOCAL_SERVER | REMOTE_SERVER

// readConditions reads the power source and the cost of the PC's internet
// connection (as Windows reports it: "Metered connection" in the network's
// settings, or a cellular data plan).
func readConditions() (conditions, error) {
	var c conditions
	var errs []error
	var ps systemPowerStatus
	if ok, _, e := procGetSystemPowerStatus.Call(uintptr(unsafe.Pointer(&ps))); ok == 0 {
		errs = append(errs, fmt.Errorf("GetSystemPowerStatus: %w", e))
	} else {
		c.Battery = ps.ACLineStatus == 0
	}
	cost, err := connectionCost()
	if err != nil {
		errs = append(errs, err)
	} else {
		c.Metered = cost&(nlmCostFixed|nlmCostVariable|nlmCostOverDataLimit|nlmCostRoaming) != 0
	}
	return c, errors.Join(errs...)
}

// connectionCost asks the Network List Manager for the cost of the machine's
// internet connection (INetworkCostManager::GetCost).
func connectionCost() (uint32, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.CoInitializeEx(0, windows.COINIT_MULTITHREADED); err != nil && err != syscall.Errno(1) { // S_FALSE: already initialized
		return 0, fmt.Errorf("CoInitializeEx: %w", err)
	}
	defer windows.CoUninitialize()
	var mgr *struct{ vtbl *[4]uintptr } // IUnknown (3 methods) + GetCost
	if hr, _, _ := procCoCreateInstance.Call(uintptr(unsafe.Pointer(&clsidNetworkListManager)), 0, clsctxAll,
		uintptr(unsafe.Pointer(&iidINetworkCostManager)), uintptr(unsafe.Pointer(&mgr))); hr != 0 {
		return 0, fmt.Errorf("CoCreateInstance(NetworkListManager): %w", syscall.Errno(hr))
	}
	defer syscall.SyscallN(mgr.vtbl[2], uintptr(unsafe.Pointer(mgr))) // Release
	var cost uint32
	if hr, _, _ := syscall.SyscallN(mgr.vtbl[3], uintptr(unsafe.Pointer(mgr)), uintptr(unsafe.Pointer(&cost)), 0); hr != 0 {
		return 0, fmt.Errorf("INetworkCostManager.GetCost: %w", syscall.Errno(hr))
	}
	return cost, nil
}
