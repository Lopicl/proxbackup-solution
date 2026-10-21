// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"errors"
	"testing"
	"time"
	"unsafe"
)

func TestKeepAwake(t *testing.T) {
	// REASON_CONTEXT: two ULONGs and a union of a pointer or {HMODULE, ULONG, ULONG, LPWSTR*}.
	if want := 8 + 2*unsafe.Sizeof(uintptr(0)) + 8; unsafe.Sizeof(reasonContext{}) != want {
		t.Fatalf("reasonContext is %d bytes, want %d", unsafe.Sizeof(reasonContext{}), want)
	}
	release, err := keepAwake("ProxBackup test")
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestSetWakeTimer(t *testing.T) {
	if err := setWakeTimer(time.Now().Add(time.Hour)); errors.Is(err, errNoWake) {
		t.Log(err) // e.g. a VM without sleep states
	} else if err != nil {
		t.Fatal(err)
	}
	if err := setWakeTimer(time.Time{}); err != nil {
		t.Fatal(err)
	}
}
