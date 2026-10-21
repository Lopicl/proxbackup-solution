// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"testing"
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
