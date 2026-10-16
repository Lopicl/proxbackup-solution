// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"proxbackup/internal/api"
	"proxbackup/pkg/pbs"
)

// cryptConfig turns the key the server sent into a crypt config (nil, nil
// without a key).
func cryptConfig(k *api.CryptKey) (*pbs.CryptConfig, error) {
	if k == nil || k.Key == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(k.Key)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("invalid encryption key")
	}
	c, err := pbs.NewCryptConfig([32]byte(raw))
	if err != nil {
		return nil, err
	}
	if k.Fingerprint != "" && pbs.NormalizeFingerprint(k.Fingerprint) != pbs.NormalizeFingerprint(c.Fingerprint()) {
		return nil, errors.New("encryption key does not match its fingerprint")
	}
	return c, nil
}

// initCrypt loads the client key; backups fail if they should be encrypted
// but no key came with the job.
func (j *job) initCrypt() error {
	c, err := cryptConfig(j.spec.Crypt)
	if err != nil {
		return err
	}
	j.crypt = c
	if j.spec.Encrypt && j.spec.Kind != api.KindRestore {
		if c == nil {
			return errors.New("encryption is enabled for this job, but the console sent no encryption key")
		}
		j.logf("info", "client-side encryption on, key %s", c.Fingerprint())
	}
	return nil
}

// backupCrypt is the crypt config new snapshots are written with (nil = unencrypted).
func (j *job) backupCrypt() *pbs.CryptConfig {
	if j.spec.Encrypt {
		return j.crypt
	}
	return nil
}

// sameCrypt reports whether a previous snapshot was written the way this
// backup writes, so its chunks may be reused.
func (j *job) sameCrypt(m *pbs.Manifest) bool {
	c := j.backupCrypt()
	if c == nil || !m.Encrypted() {
		return c == nil && !m.Encrypted()
	}
	return pbs.NormalizeFingerprint(m.KeyFingerprint()) == pbs.NormalizeFingerprint(c.Fingerprint())
}

// uploadMasterKeyCopy stores the key encrypted with the master public key in
// the snapshot (rsa-encrypted.key.blob), so it can be recovered without the
// console. A failure is logged: the console still holds the key.
func (j *job) uploadMasterKeyCopy(ctx context.Context, s *pbs.BackupSession) error {
	k := j.spec.Crypt
	if j.backupCrypt() == nil || k.MasterPubKey == "" {
		return nil
	}
	pub, err := pbs.ParseRSAPublicKey([]byte(k.MasterPubKey))
	if err == nil {
		var raw []byte
		if raw, err = pbs.RSAEncryptedKey(pub, [32]byte(j.keyBytes()), time.Unix(k.Created, 0)); err == nil {
			return s.UploadBlob(ctx, pbs.RSAKeyBlobName, raw, false)
		}
	}
	j.logf("warn", "no master-key copy of the encryption key in this snapshot: %v", err)
	return nil
}

func (j *job) keyBytes() []byte {
	raw, _ := base64.StdEncoding.DecodeString(j.spec.Crypt.Key)
	return raw
}

// checkRestoreKey explains why an encrypted snapshot can't be read.
func (j *job) checkRestoreKey(m *pbs.Manifest, ref pbs.SnapshotRef) error {
	if m.Encrypted() && j.crypt == nil {
		return fmt.Errorf("snapshot %s is encrypted (key %s), but this client has no encryption key", ref, m.KeyFingerprint())
	}
	return nil
}

// KeyFromFile reads a PBS key file (as downloaded from the console) for the
// ad-hoc commands.
func KeyFromFile(data []byte) (*api.CryptKey, error) {
	key, err := pbs.ParseKeyFile(data)
	if err != nil {
		return nil, err
	}
	c, err := pbs.NewCryptConfig(key)
	if err != nil {
		return nil, err
	}
	return &api.CryptKey{Key: base64.StdEncoding.EncodeToString(key[:]), Fingerprint: c.Fingerprint(), Created: time.Now().Unix()}, nil
}
