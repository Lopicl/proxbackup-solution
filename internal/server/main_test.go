// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"os"
	"testing"
)

// TestMain lets webhooks reach the tests' loopback servers.
func TestMain(m *testing.M) {
	webhookAddrCheck = func(string) error { return nil }
	os.Exit(m.Run())
}
