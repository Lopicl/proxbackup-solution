// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"testing"
	"unsafe"
)

func TestReadConditions(t *testing.T) {
	if unsafe.Sizeof(systemPowerStatus{}) != 12 {
		t.Fatalf("systemPowerStatus is %d bytes, want 12", unsafe.Sizeof(systemPowerStatus{}))
	}
	cost, err := connectionCost()
	if err != nil {
		t.Fatal(err)
	}
	c, err := readConditions()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("cost %#x, conditions %+v", cost, c)
}
