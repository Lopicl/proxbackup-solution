// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kardianos/service"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"proxbackup/internal/agent"
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

// installService installs the agent (see installAgent) and starts the service.
func installService(dataDir string) error {
	if err := installAgent(dataDir); err != nil {
		return err
	}
	if err := serviceCommand("start", dataDir, slog.Default(), nil); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	fmt.Println("The ProxBackup Agent service is running. This PC now appears under Clients in the ProxBackup Console.")
	return nil
}

// installAgent copies the agent to Program Files (without the setup token a
// setup .exe carries) and installs the service from there, wherever this copy
// was started from: a service run by SYSTEM must not live in a folder users
// can write to. An existing service is stopped and pointed at the new copy;
// one already set up that way is left as it is. If anything fails after the
// service was stopped, it is started again as it was.
func installAgent(dataDir string) (retErr error) {
	if _, err := agent.SecureDataDir(dataDir); err != nil {
		return err
	}
	src, err := os.Executable()
	if err != nil {
		return err
	}
	dst := installPath()
	fromDst := strings.EqualFold(filepath.Clean(src), dst)
	binPath := servicePath(dst, dataDir)

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err == nil {
		defer s.Close()
		cfg, err := s.Config()
		if err != nil {
			return err
		}
		if fromDst && strings.EqualFold(cfg.BinaryPathName, binPath) {
			fmt.Println("service install: already installed in", filepath.Dir(dst))
			return nil
		}
		running := false
		if st, err := s.Query(); err == nil && st.State != svc.Stopped {
			running = true
		}
		fmt.Println("Stopping the existing ProxBackup Agent service ...")
		if err := stopService(s); err != nil {
			return err
		}
		if running {
			defer func() {
				if retErr != nil {
					if err := s.Start(); err != nil {
						retErr = fmt.Errorf("%w (and restarting the previous service failed: %v)", retErr, err)
					} else {
						fmt.Println("Restarted the previous ProxBackup Agent service.")
					}
				}
			}()
		}
	}
	if !fromDst {
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
		cfg.BinaryPathName = binPath
		cfg.StartType = mgr.StartAutomatic
		if err := s.UpdateConfig(cfg); err != nil {
			return fmt.Errorf("update service: %w", err)
		}
	} else {
		sv, err := newService(&program{dataDir: dataDir}, dataDir, dst)
		if err != nil {
			return err
		}
		if err := service.Control(sv, "install"); err != nil {
			return fmt.Errorf("service install: %w", err)
		}
	}
	fmt.Printf("service install: ok (%s)\n", dst)
	return nil
}

// installPath is where the agent service runs from.
func installPath() string {
	return filepath.Join(cmp.Or(os.Getenv("ProgramFiles"), `C:\Program Files`), "ProxBackup", "proxbackup-agent.exe")
}

func servicePath(exe, dataDir string) string {
	return syscall.EscapeArg(exe) + " run -data-dir " + syscall.EscapeArg(dataDir)
}

// relocate moves a service that `install` set up outside Program Files
// (before 0.2.16 it ran the exe from wherever it was downloaded) to
// Program Files: it copies this binary there and points the service at the
// copy. moved means the service must be restarted to run the copy. It only
// acts when this process is the proxbackup-agent service.
func relocate(dataDir string) (moved bool, err error) {
	src, err := os.Executable()
	if err != nil {
		return false, err
	}
	dst := installPath()
	if strings.EqualFold(filepath.Clean(src), dst) {
		return false, nil
	}
	m, err := mgr.Connect()
	if err != nil {
		return false, fmt.Errorf("service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return false, err
	}
	defer s.Close()
	if st, err := s.Query(); err != nil || st.ProcessId != uint32(os.Getpid()) {
		return false, err // another copy (a test service, or run by hand)
	}
	cfg, err := s.Config()
	if err != nil {
		return false, err
	}
	if err := copyAgent(src, dst); err != nil {
		return false, err
	}
	cfg.BinaryPathName = servicePath(dst, dataDir)
	if err := s.UpdateConfig(cfg); err != nil {
		return false, fmt.Errorf("update service: %w", err)
	}
	return true, nil
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

// copyAgent writes the plain agent (src without a setup trailer) to dst. A
// running copy of dst (the tray app) is moved aside, as self-update does; the
// stopped service's process may hold the old file for a moment: retry. The
// tray notices the new file and restarts from it.
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
		if err = agent.ReplaceExe(tmp, dst); err == nil || i == 20 {
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
