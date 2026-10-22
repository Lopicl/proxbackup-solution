// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Log file rotation: agent.log is renamed to agent.log.1 (and so on) once it
// reaches logMaxSize; logKeep old files are kept.
const (
	logMaxSize = 5 << 20
	logKeep    = 3
)

// LogFile is a size-rotated log file. The service has no console, so this is
// where its log ends up (<data dir>\logs\agent.log).
type LogFile struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

// LogDir is the directory of the agent's log files.
func LogDir(dataDir string) string { return filepath.Join(dataDir, "logs") }

// OpenLogFile opens (appending) the agent log in dataDir.
func OpenLogFile(dataDir string) (*LogFile, error) {
	dir := LogDir(dataDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	l := &LogFile{path: filepath.Join(dir, "agent.log")}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *LogFile) open() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.f, l.size = f, st.Size()
	return nil
}

func (l *LogFile) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return 0, os.ErrClosed
	}
	if l.size > 0 && l.size+int64(len(p)) > logMaxSize {
		l.rotate()
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	return n, err
}

// rotate shifts agent.log.N up by one and starts a new agent.log. On failure
// it keeps writing to the current file.
func (l *LogFile) rotate() {
	l.f.Close()
	for i := logKeep - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", l.path, i), fmt.Sprintf("%s.%d", l.path, i+1))
	}
	os.Rename(l.path, l.path+".1")
	if err := l.open(); err != nil {
		// Can't create a new file (e.g. renamed but no longer writable): reopen
		// whatever is there rather than dropping the log.
		l.f, _ = os.OpenFile(l.path+".1", os.O_WRONLY|os.O_APPEND, 0o644)
		l.size = 0
	}
}

// Close closes the file.
func (l *LogFile) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
