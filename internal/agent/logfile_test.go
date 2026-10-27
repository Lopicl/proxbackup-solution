// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestLogFileRotation(t *testing.T) {
	dir := t.TempDir()
	l, err := OpenLogFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	line := bytes.Repeat([]byte("x"), 1<<20)
	for i := 0; i < 5*(logKeep+2); i++ {
		if _, err := l.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	base := filepath.Join(LogDir(dir), "agent.log")
	for i := 0; i <= logKeep; i++ {
		p := base
		if i > 0 {
			p = fmt.Sprintf("%s.%d", base, i)
		}
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() > logMaxSize {
			t.Errorf("%s: %d bytes, over the limit", p, st.Size())
		}
	}
	if _, err := os.Stat(fmt.Sprintf("%s.%d", base, logKeep+1)); !os.IsNotExist(err) {
		t.Errorf("more than %d old log files kept", logKeep)
	}

	// Reopening appends.
	dir = t.TempDir()
	for range 2 {
		l, _ = OpenLogFile(dir)
		l.Write([]byte("hello\n"))
		l.Close()
	}
	if b, _ := os.ReadFile(filepath.Join(LogDir(dir), "agent.log")); string(b) != "hello\nhello\n" {
		t.Errorf("reopen: %q", b)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("no console") }

// A service has no valid stderr: the file must still get every line.
func TestLogFileWithBrokenConsole(t *testing.T) {
	dir := t.TempDir()
	l, err := OpenLogFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	w := l.WithConsole(failWriter{})
	if _, err := w.Write([]byte("hello\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	var nilFile *os.File // what os.Stderr is when the process has no stderr handle
	if _, err := l.WithConsole(nilFile).Write([]byte("world\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	l.Close()
	b, err := os.ReadFile(filepath.Join(LogDir(dir), "agent.log"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello\nworld\n" {
		t.Errorf("log file = %q", b)
	}
}
