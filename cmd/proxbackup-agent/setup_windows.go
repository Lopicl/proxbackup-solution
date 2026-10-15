// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kardianos/service"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "proxbackup-agent"

// elevate restarts this program with administrator rights (UAC prompt) when it
// lacks them. relaunched is true when the elevated copy took over.
func elevate() (relaunched bool, err error) {
	if windows.GetCurrentProcessToken().IsElevated() {
		return false, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return false, err
	}
	args := make([]string, len(os.Args)-1)
	for i, a := range os.Args[1:] {
		args[i] = syscall.EscapeArg(a)
	}
	cwd, _ := os.Getwd()
	err = windows.ShellExecute(0, windows.StringToUTF16Ptr("runas"), windows.StringToUTF16Ptr(exe),
		windows.StringToUTF16Ptr(strings.Join(args, " ")), windows.StringToUTF16Ptr(cwd), windows.SW_NORMAL)
	if err != nil {
		return false, fmt.Errorf("administrator rights are needed: %w", err)
	}
	return true, nil
}

// installService copies the agent to Program Files (without the setup token
// a setup .exe carries) and installs and starts the service from there. An
// existing service is stopped and pointed at the new copy.
func installService(dataDir string) error {
	src, err := os.Executable()
	if err != nil {
		return err
	}
	dst := filepath.Join(cmp.Or(os.Getenv("ProgramFiles"), `C:\Program Files`), "ProxBackup", "proxbackup-agent.exe")

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err == nil {
		defer s.Close()
		fmt.Println("Stopping the existing ProxBackup Agent service ...")
		if err := stopService(s); err != nil {
			return err
		}
	}
	if !strings.EqualFold(filepath.Clean(src), dst) {
		fmt.Println("Installing", dst)
		if err := copyAgent(src, dst); err != nil {
			return err
		}
	}
	if s != nil {
		cfg, err := s.Config()
		if err != nil {
			return err
		}
		cfg.BinaryPathName = syscall.EscapeArg(dst) + " run -data-dir " + syscall.EscapeArg(dataDir)
		cfg.StartType = mgr.StartAutomatic
		if err := s.UpdateConfig(cfg); err != nil {
			return fmt.Errorf("update service: %w", err)
		}
		if err := s.Start(); err != nil {
			return fmt.Errorf("start service: %w", err)
		}
	} else {
		sv, err := newService(&program{dataDir: dataDir}, dataDir, dst)
		if err != nil {
			return err
		}
		for _, c := range []string{"install", "start"} {
			if err := service.Control(sv, c); err != nil {
				return fmt.Errorf("service %s: %w", c, err)
			}
		}
	}
	fmt.Println("The ProxBackup Agent service is running. This PC now appears under Clients in the ProxBackup Console.")
	return nil
}

func stopService(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil && st.State != svc.StopPending {
			return fmt.Errorf("stop service: %w", err)
		}
	}
	for deadline := time.Now().Add(45 * time.Second); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		if st, err = s.Query(); err != nil || st.State == svc.Stopped {
			return err
		}
	}
	return errors.New("the ProxBackup Agent service did not stop within 45s")
}

// copyAgent writes the plain agent (src without a setup trailer) to dst. The
// stopped service's process may hold the old file for a moment: retry.
func copyAgent(src, dst string) error {
	size := int64(-1)
	if _, n, ok := embeddedSetupToken(); ok {
		size = n
	}
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".new"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	var r io.Reader = f
	if size >= 0 {
		r = io.LimitReader(f, size)
	}
	_, err = io.Copy(out, r)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	for i := 0; ; i++ {
		if err = os.Rename(tmp, dst); err == nil || i == 20 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replace %s: %w", dst, err)
	}
	return nil
}
