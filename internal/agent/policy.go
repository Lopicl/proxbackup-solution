// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Policy is what the PC's administrators allow the console, kept in
// policy.json in the data directory: only SYSTEM and Administrators can
// write there (SecureDataDir), so a compromised console can't change it.
type Policy struct {
	// ConsoleSystemRestores lets console users with the "Restore to system
	// folders" permission restore into Windows, Program Files and the other
	// protected folders (api.RestoreSpec.SystemFolders). Restores run as
	// SYSTEM, so that lets the console run code on the PC. Nil (installs
	// from before the policy) means allowed; new installs write false.
	ConsoleSystemRestores *bool `json:"console_system_restores,omitempty"`
}

const policyFile = "policy.json"

// LoadPolicy reads the policy in dir; a missing file is the zero Policy.
func LoadPolicy(dir string) (Policy, error) {
	var p Policy
	b, err := readSecret(filepath.Join(dir, policyFile))
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	return p, json.Unmarshal(b, &p)
}

// SavePolicy writes p to dir.
func SavePolicy(dir string, p Policy) error {
	b, _ := json.MarshalIndent(p, "", "  ")
	return writeSecret(filepath.Join(dir, policyFile), b)
}

// SystemRestoresAllowed reports whether console restores may write into
// system folders.
func (p Policy) SystemRestoresAllowed() bool {
	return p.ConsoleSystemRestores == nil || *p.ConsoleSystemRestores
}

// initPolicy gives a new install (no agent.json and no policy yet) the
// restrictive default: no console restores into system folders.
func initPolicy(dir string) error {
	for _, name := range []string{"agent.json", policyFile} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	off := false
	return SavePolicy(dir, Policy{ConsoleSystemRestores: &off})
}
