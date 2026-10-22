// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bytes"
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
