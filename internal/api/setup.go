// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// A setup .exe is the agent binary followed by a trailer:
//
//	agent exe ‖ token ‖ uint32 LE len(token) ‖ SetupTrailerMagic
//
// Windows ignores data after the PE image, so the file still runs as the agent,
// which finds the token in its own executable and starts the interactive setup.
const SetupTrailerMagic = "PBXSETUP"

const maxSetupToken = 64 << 10

// SetupTrailer returns the bytes to append to an agent binary.
func SetupTrailer(token string) []byte {
	b := make([]byte, 0, len(token)+4+len(SetupTrailerMagic))
	b = append(b, token...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(token)))
	return append(b, SetupTrailerMagic...)
}

// ReadSetupTrailer returns the setup token appended to an executable of the
// given size and the size of the executable without it. ok is false when the
// file has no trailer.
func ReadSetupTrailer(r io.ReaderAt, size int64) (token string, exeSize int64, ok bool, err error) {
	tail := int64(4 + len(SetupTrailerMagic))
	if size < tail {
		return "", size, false, nil
	}
	buf := make([]byte, tail)
	if _, err := r.ReadAt(buf, size-tail); err != nil {
		return "", size, false, err
	}
	if !bytes.Equal(buf[4:], []byte(SetupTrailerMagic)) {
		return "", size, false, nil
	}
	n := int64(binary.LittleEndian.Uint32(buf))
	if n > maxSetupToken || n > size-tail {
		return "", size, false, errors.New("corrupt setup trailer")
	}
	tok := make([]byte, n)
	if _, err := r.ReadAt(tok, size-tail-n); err != nil {
		return "", size, false, err
	}
	return string(tok), size - tail - n, true, nil
}
