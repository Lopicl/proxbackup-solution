// Command mkdeb builds the proxbackup-server .deb from packaging/deb without
// needing dpkg, so it works on macOS and in CI alike.
//
//	go run ./tools/mkdeb -arch amd64 -version 0.1.2.3 -binary bin/proxbackup-server-linux-amd64 -out bin
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type file struct {
	path string // inside the package, e.g. "usr/bin/proxbackup-server"
	mode int64
	data []byte
}

func main() {
	arch := flag.String("arch", "amd64", "Debian architecture")
	version := flag.String("version", "", "package version")
	binary := flag.String("binary", "", "linux proxbackup-server binary")
	src := flag.String("src", "packaging/deb", "packaging directory")
	out := flag.String("out", "bin", "output directory")
	flag.Parse()
	if *version == "" || *binary == "" {
		fatal(fmt.Errorf("-version and -binary are required"))
	}
	read := func(p string) []byte {
		b, err := os.ReadFile(p)
		if err != nil {
			fatal(err)
		}
		return b
	}

	data := []file{
		{"usr/bin/proxbackup-server", 0o755, read(*binary)},
		{"usr/lib/systemd/system/proxbackup-server.service", 0o644, read(filepath.Join(*src, "proxbackup-server.service"))},
	}
	var size int
	for _, f := range data {
		size += len(f.data)
	}
	control := strings.NewReplacer("@VERSION@", *version, "@ARCH@", *arch, "@SIZE@", strconv.Itoa((size+1023)/1024)).
		Replace(string(read(filepath.Join(*src, "control"))))
	ctrl := []file{{"control", 0o644, []byte(control)}}
	for _, s := range []string{"postinst", "prerm", "postrm"} {
		ctrl = append(ctrl, file{s, 0o755, read(filepath.Join(*src, s))})
	}

	name := filepath.Join(*out, fmt.Sprintf("proxbackup-server_%s_%s.deb", *version, *arch))
	var deb bytes.Buffer
	deb.WriteString("!<arch>\n")
	arMember(&deb, "debian-binary", []byte("2.0\n"))
	arMember(&deb, "control.tar.gz", tarGz(ctrl))
	arMember(&deb, "data.tar.gz", tarGz(data))
	if err := os.WriteFile(name, deb.Bytes(), 0o644); err != nil {
		fatal(err)
	}
	fmt.Println(name)
}

var mtime = time.Now()

// tarGz writes files (and their parent directories) owned by root.
func tarGz(files []file) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	dirs := map[string]bool{}
	hdr := func(h *tar.Header) {
		h.Uname, h.Gname, h.ModTime, h.Format = "root", "root", mtime, tar.FormatGNU
		if err := tw.WriteHeader(h); err != nil {
			fatal(err)
		}
	}
	for _, f := range files {
		var parents []string
		for d := filepath.Dir(f.path); d != "."; d = filepath.Dir(d) {
			parents = append([]string{d}, parents...)
		}
		for _, d := range parents {
			if !dirs[d] {
				dirs[d] = true
				hdr(&tar.Header{Typeflag: tar.TypeDir, Name: "./" + d + "/", Mode: 0o755})
			}
		}
		hdr(&tar.Header{Typeflag: tar.TypeReg, Name: "./" + f.path, Mode: f.mode, Size: int64(len(f.data))})
		if _, err := tw.Write(f.data); err != nil {
			fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		fatal(err)
	}
	if err := gz.Close(); err != nil {
		fatal(err)
	}
	return buf.Bytes()
}

// arMember appends one member in the common ar format dpkg reads.
func arMember(w *bytes.Buffer, name string, data []byte) {
	fmt.Fprintf(w, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", name, mtime.Unix(), 0, 0, "100644", len(data))
	w.Write(data)
	if len(data)%2 == 1 {
		w.WriteByte('\n')
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "mkdeb:", err)
	os.Exit(1)
}
