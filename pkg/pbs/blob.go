// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pbs implements the client side of the Proxmox Backup Server protocol.
//
// The wire formats here mirror the upstream Rust implementation in
// proxmox-backup (pbs-datastore/src/file_formats.rs, data_blob.rs).
package pbs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/pbkdf2"
)

// Blob magic numbers: sha256("Proxmox Backup ... v1.0")[0..8].
var (
	MagicUncompressed     = [8]byte{66, 171, 56, 7, 190, 131, 112, 161}
	MagicCompressed       = [8]byte{49, 185, 88, 66, 111, 182, 163, 127}
	MagicEncrypted        = [8]byte{123, 103, 133, 190, 34, 45, 76, 240}
	MagicEncrCompr        = [8]byte{230, 89, 27, 191, 11, 191, 216, 11}
	MagicFixedIndex       = [8]byte{47, 127, 65, 237, 145, 253, 15, 205}
	MagicDynamicIndex     = [8]byte{28, 145, 78, 165, 25, 186, 179, 205}
	MagicCatalogFile      = [8]byte{145, 253, 96, 249, 196, 103, 88, 213}
	errUnknownBlobMagic   = errors.New("pbs: unknown blob magic")
	errBlobCRC            = errors.New("pbs: blob CRC mismatch")
	errDecryptNeedsConfig = errors.New("pbs: blob is encrypted but no crypt config given")
)

const (
	blobHeaderSize          = 12      // magic(8) + crc(4)
	encryptedBlobHeaderSize = 12 + 32 // + iv(16) + tag(16)
	maxBlobSize             = 128 << 20
)

var (
	zstdEnc, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithEncoderConcurrency(1))
	zstdDec, _ = zstd.NewReader(nil, zstd.WithDecoderConcurrency(0))
)

// CryptConfig holds the AES-256-GCM key used for client-side encryption.
type CryptConfig struct {
	encKey [32]byte
	idKey  [32]byte
	gcm    cipher.AEAD // AES-256-GCM with the 16 byte IV PBS uses
}

// NewCryptConfig derives the id key exactly like pbs-tools CryptConfig::new.
func NewCryptConfig(encKey [32]byte) (*CryptConfig, error) {
	block, err := aes.NewCipher(encKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}
	c := &CryptConfig{encKey: encKey, gcm: gcm}
	copy(c.idKey[:], pbkdf2.Key(encKey[:], []byte("_id_key"), 10, 32, sha256.New))
	return c, nil
}

// ComputeDigest returns the chunk digest. Without encryption this is plain
// sha256(data); with encryption the id key is appended to avoid leaking content hashes.
func (c *CryptConfig) ComputeDigest(data []byte) [32]byte {
	if c == nil {
		return sha256.Sum256(data)
	}
	h := sha256.New()
	h.Write(data)
	h.Write(c.idKey[:])
	var d [32]byte
	h.Sum(d[:0])
	return d
}

// EncodeBlob encodes data as a PBS data blob, compressing with zstd when that
// makes it smaller, and encrypting when crypt is non-nil.
func EncodeBlob(data []byte, crypt *CryptConfig, compress bool) ([]byte, error) {
	if len(data) > maxBlobSize {
		return nil, fmt.Errorf("pbs: data blob too large (%d bytes)", len(data))
	}
	payload := data
	compressed := false
	if compress {
		c := zstdEnc.EncodeAll(data, make([]byte, 0, len(data)/2+64))
		if len(c) <= len(data) {
			payload, compressed = c, true
		}
	}

	var magic [8]byte
	switch {
	case compressed && crypt != nil:
		magic = MagicEncrCompr
	case compressed:
		magic = MagicCompressed
	case crypt != nil:
		magic = MagicEncrypted
	default:
		magic = MagicUncompressed
	}

	var out []byte
	if crypt != nil {
		var iv [16]byte
		if _, err := rand.Read(iv[:]); err != nil {
			return nil, err
		}
		sealed := crypt.gcm.Seal(nil, iv[:], payload, nil) // ciphertext || tag(16)
		ct, tag := sealed[:len(sealed)-16], sealed[len(sealed)-16:]
		out = make([]byte, encryptedBlobHeaderSize, encryptedBlobHeaderSize+len(ct))
		copy(out[12:28], iv[:])
		copy(out[28:44], tag)
		out = append(out, ct...)
	} else {
		out = make([]byte, blobHeaderSize, blobHeaderSize+len(payload))
		out = append(out, payload...)
	}
	copy(out[0:8], magic[:])
	hdr := headerSize(magic)
	binary.LittleEndian.PutUint32(out[8:12], crc32.ChecksumIEEE(out[hdr:]))
	return out, nil
}

// DecodeBlob verifies the CRC and returns the decoded (decrypted, decompressed) data.
func DecodeBlob(raw []byte, crypt *CryptConfig) ([]byte, error) {
	if len(raw) < blobHeaderSize {
		return nil, errors.New("pbs: blob too short")
	}
	var magic [8]byte
	copy(magic[:], raw[:8])
	hdr := headerSize(magic)
	if hdr == 0 {
		return nil, errUnknownBlobMagic
	}
	if len(raw) < hdr {
		return nil, errors.New("pbs: blob too short")
	}
	if binary.LittleEndian.Uint32(raw[8:12]) != crc32.ChecksumIEEE(raw[hdr:]) {
		return nil, errBlobCRC
	}
	switch magic {
	case MagicUncompressed:
		return bytes.Clone(raw[hdr:]), nil
	case MagicCompressed:
		return zstdDec.DecodeAll(raw[hdr:], nil)
	}
	if crypt == nil {
		return nil, errDecryptNeedsConfig
	}
	iv, tag := raw[12:28], raw[28:44]
	sealed := append(bytes.Clone(raw[hdr:]), tag...)
	plain, err := crypt.gcm.Open(nil, iv, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("pbs: blob decryption failed: %w", err)
	}
	if magic == MagicEncrCompr {
		return zstdDec.DecodeAll(plain, nil)
	}
	return plain, nil
}

// BlobIsEncrypted reports whether raw has an encrypted blob magic.
func BlobIsEncrypted(raw []byte) bool {
	if len(raw) < 8 {
		return false
	}
	return bytes.Equal(raw[:8], MagicEncrypted[:]) || bytes.Equal(raw[:8], MagicEncrCompr[:])
}

func headerSize(magic [8]byte) int {
	switch magic {
	case MagicUncompressed, MagicCompressed:
		return blobHeaderSize
	case MagicEncrypted, MagicEncrCompr:
		return encryptedBlobHeaderSize
	}
	return 0
}
