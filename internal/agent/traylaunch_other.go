// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package agent

import (
	"context"
	"log/slog"
)

// launchTrays: the tray app is Windows-only.
func launchTrays(context.Context, *slog.Logger) {}
