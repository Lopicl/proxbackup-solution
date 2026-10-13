// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package main

import "errors"

func reexec() error { return errors.New("restart the server to run the updated binary") }
