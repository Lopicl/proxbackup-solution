// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"testing"
)

func TestSetupTrailer(t *testing.T) {
	exe := []byte("MZ\x90\x00 pretend this is a PE image")
	file := append(append([]byte{}, exe...), SetupTrailer("eyJ1IjoiaHR0cHM6Ly94In0")...)
	tok, n, ok, err := ReadSetupTrailer(bytes.NewReader(file), int64(len(file)))
	if err != nil || !ok || tok != "eyJ1IjoiaHR0cHM6Ly94In0" || n != int64(len(exe)) {
		t.Fatalf("got %q %d %v %v", tok, n, ok, err)
	}
	for _, plain := range [][]byte{exe, nil, []byte("PBXSETUP")} {
		if _, n, ok, err := ReadSetupTrailer(bytes.NewReader(plain), int64(len(plain))); ok || err != nil || n != int64(len(plain)) {
			t.Fatalf("plain %q: got %d %v %v", plain, n, ok, err)
		}
	}
	bad := append(append([]byte{}, exe...), 0xff, 0xff, 0xff, 0x7f)
	bad = append(bad, SetupTrailerMagic...)
	if _, _, ok, err := ReadSetupTrailer(bytes.NewReader(bad), int64(len(bad))); ok || err == nil {
		t.Fatalf("corrupt trailer accepted")
	}
}
