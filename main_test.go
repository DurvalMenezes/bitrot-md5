package main

import (
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"syscall"	
)

// ── Helpers ──────────────────────────────────────────────────────────

func createTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "bitrot-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	var buf strings.Builder
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func knownMD5(content string) string {
	h := md5.Sum([]byte(content))
	return hex.EncodeToString(h[:])
}

func ageFile(t *testing.T, path string, d time.Duration) {
	t.Helper()
	past := time.Now().Add(-d)
	if err := os.Chtimes(path, past, past); err != nil {
		t.Fatal(err)
	}
}

func runScan(t *testing.T, cf, root, uf string, workers int, verbose, summary bool) (bool, string) {
	t.Helper()
	var bitrot bool
	out := captureStdout(t, func() {
		var err error
		bitrot, err = scan(cf, root, uf, workers, verbose, summary)
		if err != nil {
			t.Fatal(err)
		}
	})
	return bitrot, out
}

func seedChecksums(t *testing.T, dir, cf string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		writeFile(t, filepath.Join(dir, name), content)
	}
	if _, err := scan(cf, dir, cf, 0, false, false); err != nil {
		t.Fatal(err)
	}
}

func keysOf(m map[string]fileEntry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// ── normalizeArgs ────────────────────────────────────────────────────

func TestNormalizeArgs(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "double dash to single",
			input: []string{"prog", "--verbose", "--update", "file.md5"},
			want:  []string{"prog", "-verbose", "-update", "file.md5"},
		},
		{
			name:  "single dash preserved",
			input: []string{"prog", "-v", "-u", "file.md5"},
			want:  []string{"prog", "-v", "-u", "file.md5"},
		},
		{
			name:  "equals syntax preserved",
			input: []string{"prog", "--update=file.md5", "-v"},
			want:  []string{"prog", "-update=file.md5", "-v"},
		},
		{
			name:  "positional moved to end",
			input: []string{"prog", "checksum.md5", "-v"},
			want:  []string{"prog", "-v", "checksum.md5"},
		},
		{
			name:  "interleaved flags and positionals",
			input: []string{"prog", "-v", "checksum.md5", "-s"},
			want:  []string{"prog", "-v", "-s", "checksum.md5"},
		},
		{
			name:  "flag value consumed as pair",
			input: []string{"prog", "-u", "output.md5", "input.md5"},
			want:  []string{"prog", "-u", "output.md5", "input.md5"},
		},
		{
			name:  "flag value with equals not consumed from next",
			input: []string{"prog", "-u=output.md5", "input.md5"},
			want:  []string{"prog", "-u=output.md5", "input.md5"},
		},
		{
			name:  "double dash stops processing",
			input: []string{"prog", "-v", "--", "--not-a-flag"},
			want:  []string{"prog", "-v", "--not-a-flag"},
		},
		{
			name:  "bare parallel does not consume next arg",
			input: []string{"prog", "--parallel", "checksum.md5"},
			want:  []string{"prog", "-parallel", "checksum.md5"},
		},
		{
			name:  "parallel with equals",
			input: []string{"prog", "--parallel=4", "checksum.md5"},
			want:  []string{"prog", "-parallel=4", "checksum.md5"},
		},
		{
			name:  "multiple positionals moved",
			input: []string{"prog", "a.md5", "b.md5", "-v"},
			want:  []string{"prog", "-v", "a.md5", "b.md5"},
		},
		{
			name:  "root flag consumes value",
			input: []string{"prog", "-r", "/tmp", "-v", "input.md5"},
			want:  []string{"prog", "-r", "/tmp", "-v", "input.md5"},
		},
		{
			name:  "no args",
			input: []string{"prog"},
			want:  []string{"prog"},
		},
		{
			name:  "only positionals",
			input: []string{"prog", "a.md5", "b.md5"},
			want:  []string{"prog", "a.md5", "b.md5"},
		},
		{
			name:  "only flags",
			input: []string{"prog", "-v", "-s", "-p"},
			want:  []string{"prog", "-v", "-s", "-p"},
		},
		{
			name:  "all flags mixed",
			input: []string{"prog", "input.md5", "-v", "-u=output.md5", "-s", "-r", "/tmp"},
			want:  []string{"prog", "-v", "-u=output.md5", "-s", "-r", "/tmp", "input.md5"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = tt.input
			normalizeArgs()
			if !reflect.DeepEqual(os.Args, tt.want) {
				t.Errorf("\n  got:  %v\n  want: %v", os.Args, tt.want)
			}
		})
	}
}

// ── parseLine ────────────────────────────────────────────────────────

func TestParseLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantHash string
		wantPath string
		wantOK   bool
	}{
		{
			name:     "standard double-space format",
			line:     "d41d8cd98f00b204e9800998ecf8427e  ./file.txt",
			wantHash: "d41d8cd98f00b204e9800998ecf8427e",
			wantPath: "./file.txt",
			wantOK:   true,
		},
		{
			name:     "binary mode indicator stripped",
			line:     "d41d8cd98f00b204e9800998ecf8427e *./file.txt",
			wantHash: "d41d8cd98f00b204e9800998ecf8427e",
			wantPath: "./file.txt",
			wantOK:   true,
		},
		{
			name:     "single space separator",
			line:     "d41d8cd98f00b204e9800998ecf8427e ./file.txt",
			wantHash: "d41d8cd98f00b204e9800998ecf8427e",
			wantPath: "./file.txt",
			wantOK:   true,
		},
		{
			name:     "path with spaces",
			line:     "d41d8cd98f00b204e9800998ecf8427e  ./my file.txt",
			wantHash: "d41d8cd98f00b204e9800998ecf8427e",
			wantPath: "./my file.txt",
			wantOK:   true,
		},
		{
			name:     "nested path",
			line:     "abc123  ./sub/dir/file.txt",
			wantHash: "abc123",
			wantPath: "./sub/dir/file.txt",
			wantOK:   true,
		},
		{
			name:   "empty line",
			line:   "",
			wantOK: false,
		},
		{
			name:   "no separator at all",
			line:   "d41d8cd98f00b204e9800998ecf8427e",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, path, ok := parseLine(tt.line)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok {
				if hash != tt.wantHash {
					t.Errorf("hash = %q, want %q", hash, tt.wantHash)
				}
				if path != tt.wantPath {
					t.Errorf("path = %q, want %q", path, tt.wantPath)
				}
			}
		})
	}
}

// ── optionalInt ──────────────────────────────────────────────────────

func TestOptionalInt(t *testing.T) {
	t.Run("bare flag uses default", func(t *testing.T) {
		o := &optionalInt{defaultVal: 8}
		if err := o.Set("true"); err != nil {
			t.Fatal(err)
		}
		if !o.isSet {
			t.Error("isSet should be true")
		}
		if o.value != 8 {
			t.Errorf("value = %d, want 8", o.value)
		}
	})

	t.Run("explicit value", func(t *testing.T) {
		o := &optionalInt{defaultVal: 8}
		if err := o.Set("4"); err != nil {
			t.Fatal(err)
		}
		if o.value != 4 {
			t.Errorf("value = %d, want 4", o.value)
		}
	})

	t.Run("not set", func(t *testing.T) {
		o := &optionalInt{defaultVal: 8}
		if o.isSet {
			t.Error("isSet should be false")
		}
		if o.value != 0 {
			t.Errorf("value = %d, want 0", o.value)
		}
	})

	t.Run("invalid value", func(t *testing.T) {
		o := &optionalInt{}
		if err := o.Set("abc"); err == nil {
			t.Error("expected error for non-numeric input")
		}
	})

	t.Run("is bool flag", func(t *testing.T) {
		o := &optionalInt{}
		if !o.IsBoolFlag() {
			t.Error("IsBoolFlag should return true")
		}
	})

	t.Run("string representation", func(t *testing.T) {
		o := &optionalInt{defaultVal: 4}
		if s := o.String(); s != "0" {
			t.Errorf("unset String() = %q, want %q", s, "0")
		}
		if err := o.Set("7"); err != nil {
			t.Fatal(err)
		}
		if s := o.String(); s != "7" {
			t.Errorf("set String() = %q, want %q", s, "7")
		}
	})
}

// ── optionalString ───────────────────────────────────────────────────

func TestOptionalString(t *testing.T) {
	t.Run("bare flag gives empty value", func(t *testing.T) {
		o := &optionalString{}
		if err := o.Set("true"); err != nil {
			t.Fatal(err)
		}
		if !o.isSet {
			t.Error("isSet should be true")
		}
		if o.value != "" {
			t.Errorf("value = %q, want empty", o.value)
		}
	})

	t.Run("explicit value", func(t *testing.T) {
		o := &optionalString{}
		if err := o.Set("output.md5"); err != nil {
			t.Fatal(err)
		}
		if !o.isSet {
			t.Error("isSet should be true")
		}
		if o.value != "output.md5" {
			t.Errorf("value = %q, want %q", o.value, "output.md5")
		}
	})

	t.Run("not set", func(t *testing.T) {
		o := &optionalString{}
		if o.isSet {
			t.Error("isSet should be false")
		}
		if o.String() != "" {
			t.Errorf("String() = %q, want empty", o.String())
		}
	})

	t.Run("is bool flag", func(t *testing.T) {
		o := &optionalString{}
		if !o.IsBoolFlag() {
			t.Error("IsBoolFlag should return true")
		}
	})
}

// ── loadMD5 ──────────────────────────────────────────────────────────

func TestLoadMD5_NonExistent(t *testing.T) {
	m, err := loadMD5("/nonexistent/path/file.md5")
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 0 {
		t.Errorf("expected empty map, got %d entries", len(m))
	}
}

func TestLoadMD5_DevNull(t *testing.T) {
	m, err := loadMD5("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 0 {
		t.Errorf("expected empty map, got %d entries", len(m))
	}
}

func TestLoadMD5_Valid(t *testing.T) {
	dir := createTempDir(t)
	path := filepath.Join(dir, "test.md5")
	writeFile(t, path,
		"aaa  ./file1.txt\n"+
			"bbb  ./file2.txt\n"+
			"ccc  ./sub/file3.txt\n")

	m, err := loadMD5(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(m))
	}
	if m["./file1.txt"] != "aaa" {
		t.Errorf("file1.txt: got %q, want %q", m["./file1.txt"], "aaa")
	}
	if m["./file2.txt"] != "bbb" {
		t.Errorf("file2.txt: got %q, want %q", m["./file2.txt"], "bbb")
	}
	if m["./sub/file3.txt"] != "ccc" {
		t.Errorf("sub/file3.txt: got %q, want %q", m["./sub/file3.txt"], "ccc")
	}
}

func TestLoadMD5_BinaryMode(t *testing.T) {
	dir := createTempDir(t)
	path := filepath.Join(dir, "test.md5")
	writeFile(t, path, "aaa *./file1.txt\n")

	m, err := loadMD5(path)
	if err != nil {
		t.Fatal(err)
	}
	if m["./file1.txt"] != "aaa" {
		t.Errorf("got %q, want %q", m["./file1.txt"], "aaa")
	}
}

func TestLoadMD5_Malformed(t *testing.T) {
	dir := createTempDir(t)
	path := filepath.Join(dir, "test.md5")
	writeFile(t, path,
		"aaa  ./good.txt\n"+
			"malformed\n"+
			"bbb  ./also-good.txt\n")

	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w

	m, err := loadMD5(path)

	w.Close()
	os.Stderr = oldStderr
	r.Close()

	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 {
		t.Errorf("expected 2 entries, got %d", len(m))
	}
}

func TestLoadMD5_Empty(t *testing.T) {
	dir := createTempDir(t)
	path := filepath.Join(dir, "empty.md5")
	writeFile(t, path, "")

	m, err := loadMD5(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 0 {
		t.Errorf("expected 0 entries, got %d", len(m))
	}
}

func TestLoadMD5_Duplicates(t *testing.T) {
	dir := createTempDir(t)
	path := filepath.Join(dir, "dup.md5")
	writeFile(t, path,
		"aaa  ./file.txt\n"+
			"bbb  ./file.txt\n")

	m, err := loadMD5(path)
	if err != nil {
		t.Fatal(err)
	}
	if m["./file.txt"] != "bbb" {
		t.Errorf("got %q, want %q (last should win)", m["./file.txt"], "bbb")
	}
}

// ── saveMD5 ──────────────────────────────────────────────────────────

func TestSaveMD5(t *testing.T) {
	t.Run("writes sorted output", func(t *testing.T) {
		dir := createTempDir(t)
		path := filepath.Join(dir, "test.md5")

		db := map[string]string{
			"./b.txt": "bbb",
			"./a.txt": "aaa",
			"./c.txt": "ccc",
		}

		if err := saveMD5(path, db); err != nil {
			t.Fatal(err)
		}

		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}

		lines := strings.Split(strings.TrimSpace(string(content)), "\n")
		if len(lines) != 3 {
			t.Fatalf("expected 3 lines, got %d", len(lines))
		}
		if lines[0] != "aaa  ./a.txt" {
			t.Errorf("line 0: %q", lines[0])
		}
		if lines[1] != "bbb  ./b.txt" {
			t.Errorf("line 1: %q", lines[1])
		}
		if lines[2] != "ccc  ./c.txt" {
			t.Errorf("line 2: %q", lines[2])
		}
	})

	t.Run("empty db writes empty file", func(t *testing.T) {
		dir := createTempDir(t)
		path := filepath.Join(dir, "empty.md5")

		if err := saveMD5(path, map[string]string{}); err != nil {
			t.Fatal(err)
		}

		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(content) != 0 {
			t.Errorf("expected empty file, got %q", content)
		}
	})
}

// ── loadMD5 + saveMD5 round trip ─────────────────────────────────────

func TestLoadSaveRoundTrip(t *testing.T) {
	dir := createTempDir(t)
	path := filepath.Join(dir, "test.md5")

	original := map[string]string{
		"./file1.txt":     knownMD5("hello"),
		"./sub/file2.txt": knownMD5("world"),
		"./a.txt":         knownMD5("aaa"),
	}

	if err := saveMD5(path, original); err != nil {
		t.Fatal(err)
	}

	loaded, err := loadMD5(path)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(original, loaded) {
		t.Errorf("round trip mismatch:\n  original: %v\n  loaded:   %v", original, loaded)
	}
}

// ── discover ─────────────────────────────────────────────────────────

func TestDiscover_AllFiles(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, filepath.Join(dir, "a.txt"), "aaa")
	writeFile(t, filepath.Join(dir, "b.txt"), "bbb")
	writeFile(t, filepath.Join(dir, "sub", "c.txt"), "ccc")

	files, err := discover(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("expected 3 files, got %d", len(files))
	}
	for _, want := range []string{"./a.txt", "./b.txt", "./sub/c.txt"} {
		if _, ok := files[want]; !ok {
			t.Errorf("missing %s", want)
		}
	}
}

func TestDiscover_HiddenDirs(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, filepath.Join(dir, "a.txt"), "aaa")
	writeFile(t, filepath.Join(dir, ".hidden", "b.txt"), "bbb")

	files, err := discover(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if _, ok := files["./a.txt"]; !ok {
		t.Error("missing ./a.txt")
	}
}

func TestDiscover_MD5FilesIncluded(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, filepath.Join(dir, "a.txt"), "aaa")
	writeFile(t, filepath.Join(dir, "checksums.md5"), "data")
	writeFile(t, filepath.Join(dir, "sub", "more.MD5"), "data")

	files, err := discover(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("expected 3 files, got %d: %v", len(files), files)
	}
}

func TestDiscover_SkipMap(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, filepath.Join(dir, "a.txt"), "aaa")
	skipPath := filepath.Join(dir, "b.txt")
	writeFile(t, skipPath, "bbb")

	files, err := discover(dir, map[string]bool{skipPath: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if _, ok := files["./a.txt"]; !ok {
		t.Error("missing ./a.txt")
	}
}

func TestDiscover_Empty(t *testing.T) {
	dir := createTempDir(t)
	files, err := discover(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
}

func TestDiscover_MtimeRecorded(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, filepath.Join(dir, "a.txt"), "aaa")

	files, err := discover(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := files["./a.txt"]
	if !ok {
		t.Fatal("missing ./a.txt")
	}
	if entry.mtime.IsZero() {
		t.Error("mtime should not be zero")
	}
	if !filepath.IsAbs(entry.abs) {
		t.Errorf("abs should be absolute, got %q", entry.abs)
	}
}

func TestDiscover_ForwardSlashes(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, filepath.Join(dir, "sub", "file.txt"), "data")

	files, err := discover(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files["./sub/file.txt"]; !ok {
		t.Errorf("expected ./sub/file.txt, got keys: %v", keysOf(files))
	}
}

// ── md5File ──────────────────────────────────────────────────────────

func TestMD5File(t *testing.T) {
	dir := createTempDir(t)
	buf := make([]byte, bufSize)

	t.Run("known content", func(t *testing.T) {
		path := filepath.Join(dir, "test.txt")
		writeFile(t, path, "hello world")

		got, err := md5File(path, buf)
		if err != nil {
			t.Fatal(err)
		}
		if got != knownMD5("hello world") {
			t.Errorf("got %s, want %s", got, knownMD5("hello world"))
		}
	})

	t.Run("empty file", func(t *testing.T) {
		path := filepath.Join(dir, "empty.txt")
		writeFile(t, path, "")

		got, err := md5File(path, buf)
		if err != nil {
			t.Fatal(err)
		}
		if got != knownMD5("") {
			t.Errorf("got %s, want %s", got, knownMD5(""))
		}
	})

	t.Run("non-existent file", func(t *testing.T) {
		_, err := md5File("/nonexistent/file.txt", buf)
		if err == nil {
			t.Error("expected error for non-existent file")
		}
	})

	t.Run("large file", func(t *testing.T) {
		path := filepath.Join(dir, "large.bin")
		data := make([]byte, 1<<20)
		for i := range data {
			data[i] = byte(i % 251)
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatal(err)
		}

		got, err := md5File(path, buf)
		if err != nil {
			t.Fatal(err)
		}
		expected := knownMD5(string(data))
		if got != expected {
			t.Error("large file hash mismatch")
		}
	})
}

// ── hashSequential ───────────────────────────────────────────────────

func TestHashSequential(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, filepath.Join(dir, "a.txt"), "aaa")
	writeFile(t, filepath.Join(dir, "b.txt"), "bbb")

	infoA, _ := os.Stat(filepath.Join(dir, "a.txt"))
	infoB, _ := os.Stat(filepath.Join(dir, "b.txt"))

	files := map[string]fileEntry{
		"./a.txt": {abs: filepath.Join(dir, "a.txt"), mtime: infoA.ModTime()},
		"./b.txt": {abs: filepath.Join(dir, "b.txt"), mtime: infoB.ModTime()},
	}

	results := hashSequential(files)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	if results[0].rel != "./a.txt" {
		t.Errorf("first: got %q, want %q", results[0].rel, "./a.txt")
	}
	if results[1].rel != "./b.txt" {
		t.Errorf("second: got %q, want %q", results[1].rel, "./b.txt")
	}
	if results[0].hash != knownMD5("aaa") {
		t.Error("a.txt hash mismatch")
	}
	if results[1].hash != knownMD5("bbb") {
		t.Error("b.txt hash mismatch")
	}
	if results[0].err != nil || results[1].err != nil {
		t.Error("unexpected errors")
	}
}

// ── hashParallel ─────────────────────────────────────────────────────

func TestHashParallel(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, filepath.Join(dir, "a.txt"), "aaa")
	writeFile(t, filepath.Join(dir, "b.txt"), "bbb")
	writeFile(t, filepath.Join(dir, "c.txt"), "ccc")

	files := make(map[string]fileEntry)
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		info, _ := os.Stat(filepath.Join(dir, name))
		files["./"+name] = fileEntry{
			abs:   filepath.Join(dir, name),
			mtime: info.ModTime(),
		}
	}

	results := hashParallel(files, 2)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	resultMap := make(map[string]string)
	for _, r := range results {
		resultMap[r.rel] = r.hash
		if r.err != nil {
			t.Errorf("%s: unexpected error: %v", r.rel, r.err)
		}
	}

	if resultMap["./a.txt"] != knownMD5("aaa") {
		t.Error("a.txt mismatch")
	}
	if resultMap["./b.txt"] != knownMD5("bbb") {
		t.Error("b.txt mismatch")
	}
	if resultMap["./c.txt"] != knownMD5("ccc") {
		t.Error("c.txt mismatch")
	}
}

func TestHashParallelZeroWorkers(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, filepath.Join(dir, "a.txt"), "aaa")

	info, _ := os.Stat(filepath.Join(dir, "a.txt"))
	files := map[string]fileEntry{
		"./a.txt": {abs: filepath.Join(dir, "a.txt"), mtime: info.ModTime()},
	}

	results := hashAll(files, 0)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].hash != knownMD5("aaa") {
		t.Error("hash mismatch")
	}
}

func TestHashParallelOneWorker(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, filepath.Join(dir, "a.txt"), "aaa")
	writeFile(t, filepath.Join(dir, "b.txt"), "bbb")

	files := make(map[string]fileEntry)
	for _, name := range []string{"a.txt", "b.txt"} {
		info, _ := os.Stat(filepath.Join(dir, name))
		files["./"+name] = fileEntry{
			abs:   filepath.Join(dir, name),
			mtime: info.ModTime(),
		}
	}

	results := hashAll(files, 1)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	resultMap := make(map[string]string)
	for _, r := range results {
		resultMap[r.rel] = r.hash
	}
	if resultMap["./a.txt"] != knownMD5("aaa") || resultMap["./b.txt"] != knownMD5("bbb") {
		t.Error("hash mismatch")
	}
}

func TestParallelMatchesSequential(t *testing.T) {
	dir := createTempDir(t)
	for _, c := range []struct{ name, content string }{
		{"a.txt", "aaa"}, {"b.txt", "bbb"}, {"c.txt", "ccc"},
	} {
		writeFile(t, filepath.Join(dir, c.name), c.content)
	}

	files := make(map[string]fileEntry)
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		info, _ := os.Stat(filepath.Join(dir, name))
		files["./"+name] = fileEntry{
			abs:   filepath.Join(dir, name),
			mtime: info.ModTime(),
		}
	}

	seq := hashSequential(files)
	par := hashParallel(files, 4)

	if len(seq) != len(par) {
		t.Fatalf("length mismatch: seq=%d par=%d", len(seq), len(par))
	}

	for i := range seq {
		if seq[i].rel != par[i].rel || seq[i].hash != par[i].hash {
			t.Errorf("mismatch at %d: seq={%s:%s} par={%s:%s}",
				i, seq[i].rel, seq[i].hash, par[i].rel, par[i].hash)
		}
	}
}

// ── mustAbs ──────────────────────────────────────────────────────────

func TestMustAbs(t *testing.T) {
	abs := mustAbs(".")
	if !filepath.IsAbs(abs) {
		t.Errorf("mustAbs('.') returned relative: %s", abs)
	}
	abs = mustAbs("/tmp")
	if abs != "/tmp" {
		t.Errorf("got %s, want /tmp", abs)
	}
}

// ── scan: first run ──────────────────────────────────────────────────

func TestScanFirstRun(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, filepath.Join(dir, "a.txt"), "aaa")
	writeFile(t, filepath.Join(dir, "b.txt"), "bbb")

	cf := filepath.Join(dir, "checksums.md5")
	bitrot, out := runScan(t, cf, dir, cf, 0, false, false)

	if bitrot {
		t.Error("first run should not detect bitrot")
	}
	if !strings.Contains(out, "Wrote 2 entries") {
		t.Errorf("expected write confirmation, got:\n%s", out)
	}

	m, err := loadMD5(cf)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(m))
	}
	if m["./a.txt"] != knownMD5("aaa") {
		t.Error("a.txt checksum mismatch")
	}
	if m["./b.txt"] != knownMD5("bbb") {
		t.Error("b.txt checksum mismatch")
	}
}

func TestScanFirstRunFromDevNull(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, filepath.Join(dir, "a.txt"), "aaa")

	uf := filepath.Join(dir, "output.md5")
	bitrot, _ := runScan(t, "/dev/null", dir, uf, 0, false, false)

	if bitrot {
		t.Error("should not detect bitrot from /dev/null")
	}

	m, err := loadMD5(uf)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(m))
	}
}

func TestScanFirstRunNonExistentFile(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, filepath.Join(dir, "a.txt"), "aaa")

	cf := filepath.Join(dir, "nonexistent.md5")
	bitrot, _ := runScan(t, cf, dir, "", 0, false, false)

	if bitrot {
		t.Error("should not detect bitrot with non-existent checksum file")
	}
}

// ── scan: all OK ─────────────────────────────────────────────────────

func TestScanAllOK(t *testing.T) {
	dir := createTempDir(t)
	seedChecksums(t, dir, filepath.Join(dir, "c.md5"), map[string]string{
		"a.txt": "aaa",
		"b.txt": "bbb",
	})

	cf := filepath.Join(dir, "c.md5")

	bitrot, out := runScan(t, cf, dir, "", 0, false, false)
	if bitrot {
		t.Error("should not detect bitrot when nothing changed")
	}
	if out != "" {
		t.Errorf("expected no output, got:\n%s", out)
	}
}

func TestScanAllOKSummary(t *testing.T) {
	dir := createTempDir(t)
	seedChecksums(t, dir, filepath.Join(dir, "c.md5"), map[string]string{
		"a.txt": "aaa",
	})

	cf := filepath.Join(dir, "c.md5")
	_, out := runScan(t, cf, dir, "", 0, false, true)

	if !strings.Contains(out, "Last scan") {
		t.Errorf("expected 'Last scan' with --summary:\n%s", out)
	}
	if !strings.Contains(out, "All files OK") {
		t.Errorf("expected 'All files OK' with --summary:\n%s", out)
	}
}

// ── scan: bit rot ────────────────────────────────────────────────────

func TestScanBitRot(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	seedChecksums(t, dir, cf, map[string]string{
		"a.txt": "aaa",
		"b.txt": "bbb",
	})

	writeFile(t, filepath.Join(dir, "a.txt"), "CORRUPTED")
	ageFile(t, filepath.Join(dir, "a.txt"), 10*time.Second)

	bitrot, out := runScan(t, cf, dir, "", 0, false, false)
	if !bitrot {
		t.Error("should detect bitrot")
	}
	if !strings.Contains(out, "BIT ROT DETECTED") {
		t.Errorf("expected BIT ROT DETECTED:\n%s", out)
	}
	if !strings.Contains(out, "./a.txt") {
		t.Errorf("expected ./a.txt in output:\n%s", out)
	}
}

func TestScanBitRotDoesNotFlagModified(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	seedChecksums(t, dir, cf, map[string]string{"a.txt": "aaa"})

	ageFile(t, cf, 10*time.Second)

	writeFile(t, filepath.Join(dir, "a.txt"), "modified")

	bitrot, _ := runScan(t, cf, dir, "", 0, false, false)
	if bitrot {
		t.Error("intentional modification should not be flagged as bitrot")
	}
}

// ── scan: modified ───────────────────────────────────────────────────

func TestScanModified(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	seedChecksums(t, dir, cf, map[string]string{"a.txt": "aaa"})

	ageFile(t, cf, 10*time.Second)

	writeFile(t, filepath.Join(dir, "a.txt"), "modified")

	bitrot, out := runScan(t, cf, dir, "", 0, false, false)
	if bitrot {
		t.Error("should not detect bitrot for intentional modification")
	}
	if !strings.Contains(out, "MODIFIED") {
		t.Errorf("expected MODIFIED in output:\n%s", out)
	}
	if !strings.Contains(out, "./a.txt") {
		t.Errorf("expected ./a.txt:\n%s", out)
	}
}

// ── scan: deleted ────────────────────────────────────────────────────

func TestScanDeleted(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	seedChecksums(t, dir, cf, map[string]string{
		"a.txt": "aaa",
		"b.txt": "bbb",
	})

	os.Remove(filepath.Join(dir, "b.txt"))

	bitrot, out := runScan(t, cf, dir, "", 0, false, false)
	if bitrot {
		t.Error("deletion alone should not set bitrot flag")
	}
	if !strings.Contains(out, "DELETED") {
		t.Errorf("expected DELETED:\n%s", out)
	}
	if !strings.Contains(out, "./b.txt") {
		t.Errorf("expected ./b.txt:\n%s", out)
	}
}

// ── scan: new ────────────────────────────────────────────────────────

func TestScanNew(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	seedChecksums(t, dir, cf, map[string]string{"a.txt": "aaa"})

	writeFile(t, filepath.Join(dir, "c.txt"), "ccc")

	bitrot, out := runScan(t, cf, dir, "", 0, false, false)
	if bitrot {
		t.Error("new file should not set bitrot flag")
	}
	if !strings.Contains(out, "NEW") {
		t.Errorf("expected NEW:\n%s", out)
	}
	if !strings.Contains(out, "./c.txt") {
		t.Errorf("expected ./c.txt:\n%s", out)
	}
}

// ── scan: .md5 exclusion ─────────────────────────────────────────────

func TestScanMD5Exclusion(t *testing.T) {
    dir := createTempDir(t)
    cf := filepath.Join(dir, "checksums.md5")
    writeFile(t, filepath.Join(dir, "a.txt"), "aaa")
    writeFile(t, filepath.Join(dir, "data.md5"), "some data")

    runScan(t, cf, dir, cf, 0, false, false)

    m, _ := loadMD5(cf)
    if len(m) != 2 {
        t.Fatalf("expected 2 entries, got %d: %v", len(m), m)
    }
    if _, ok := m["./a.txt"]; !ok {
        t.Error("missing ./a.txt")
    }
    if _, ok := m["./data.md5"]; !ok {
        t.Error("./data.md5 should be included (it's a data file)")
    }
}

func TestScanMD5ExclusionCaseInsensitive(t *testing.T) {
    dir := createTempDir(t)
    cf := filepath.Join(dir, "checksums.md5")
    writeFile(t, filepath.Join(dir, "a.txt"), "aaa")
    writeFile(t, filepath.Join(dir, "UPPER.MD5"), "data")

    runScan(t, cf, dir, cf, 0, false, false)

    m, _ := loadMD5(cf)
    if len(m) != 2 {
        t.Fatalf("expected 2 entries, got %d: %v", len(m), m)
    }
}

// ── scan: checksum file exclusion ────────────────────────────────────

func TestScanChecksumFileExclusion(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, filepath.Join(dir, "a.txt"), "aaa")
	writeFile(t, filepath.Join(dir, "b.txt"), "bbb")

	cf := filepath.Join(dir, "test.md5")
	runScan(t, cf, dir, cf, 0, false, false)

	m, _ := loadMD5(cf)
	if len(m) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(m))
	}
	if _, ok := m["./test.md5"]; ok {
		t.Error("checksum file itself should be excluded")
	}
}

// ── scan: verbose output ─────────────────────────────────────────────

func TestScanVerboseBitRot(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	seedChecksums(t, dir, cf, map[string]string{
		"a.txt": "aaa",
		"b.txt": "bbb",
	})

	writeFile(t, filepath.Join(dir, "a.txt"), "CORRUPTED")
	ageFile(t, filepath.Join(dir, "a.txt"), 10*time.Second)

	_, out := runScan(t, cf, dir, "", 0, true, false)

	if !strings.Contains(out, "./a.txt: BAD") {
		t.Errorf("expected './a.txt: BAD':\n%s", out)
	}
	if !strings.Contains(out, "./b.txt: OK") {
		t.Errorf("expected './b.txt: OK':\n%s", out)
	}
}

func TestScanVerboseModified(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	seedChecksums(t, dir, cf, map[string]string{"a.txt": "aaa"})

	ageFile(t, cf, 10*time.Second)
	writeFile(t, filepath.Join(dir, "a.txt"), "modified")

	_, out := runScan(t, cf, dir, "", 0, true, false)

	if !strings.Contains(out, "./a.txt: MOD") {
		t.Errorf("expected './a.txt: MOD':\n%s", out)
	}
}

func TestScanVerboseNew(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	seedChecksums(t, dir, cf, map[string]string{"a.txt": "aaa"})

	writeFile(t, filepath.Join(dir, "b.txt"), "bbb")

	_, out := runScan(t, cf, dir, "", 0, true, false)

	if !strings.Contains(out, "./b.txt: NEW") {
		t.Errorf("expected './b.txt: NEW':\n%s", out)
	}
}

func TestScanVerboseDeleted(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	seedChecksums(t, dir, cf, map[string]string{"a.txt": "aaa"})

	os.Remove(filepath.Join(dir, "a.txt"))

	_, out := runScan(t, cf, dir, "", 0, true, false)

	if !strings.Contains(out, "./a.txt: DELETED") {
		t.Errorf("expected './a.txt: DELETED':\n%s", out)
	}
}

func TestScanVerboseAllOK(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	seedChecksums(t, dir, cf, map[string]string{"a.txt": "aaa"})

	_, out := runScan(t, cf, dir, "", 0, true, false)

	if !strings.Contains(out, "./a.txt: OK") {
		t.Errorf("expected './a.txt: OK':\n%s", out)
	}
	if !strings.Contains(out, "All files OK") {
		t.Errorf("expected 'All files OK':\n%s", out)
	}
}

// ── scan: no news = no output ────────────────────────────────────────

func TestScanSilentWhenNoNews(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	seedChecksums(t, dir, cf, map[string]string{"a.txt": "aaa"})

	_, out := runScan(t, cf, dir, "", 0, false, false)

	if out != "" {
		t.Errorf("expected silence, got:\n%s", out)
	}
}

func TestScanNoUpdatePromptWhenNoNews(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	seedChecksums(t, dir, cf, map[string]string{"a.txt": "aaa"})

	_, out := runScan(t, cf, dir, "", 0, false, false)

	if strings.Contains(out, "Checksums not written") {
		t.Errorf("should not prompt when no news:\n%s", out)
	}
}

func TestScanUpdatePromptWhenNews(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	seedChecksums(t, dir, cf, map[string]string{"a.txt": "aaa"})

	writeFile(t, filepath.Join(dir, "b.txt"), "bbb")

	_, out := runScan(t, cf, dir, "", 0, false, false)

	if !strings.Contains(out, "Checksums saved to") {
		t.Errorf("expected temp file message when new files found:\n%s", out)
	}
}

// ── scan: update file ────────────────────────────────────────────────

func TestScanUpdateFile(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	writeFile(t, filepath.Join(dir, "a.txt"), "aaa")

	uf := filepath.Join(dir, "output.md5")
	runScan(t, cf, dir, uf, 0, false, false)

	m, err := loadMD5(uf)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(m))
	}
	if m["./a.txt"] != knownMD5("aaa") {
		t.Error("output checksum mismatch")
	}
}

func TestScanUpdateInPlace(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	seedChecksums(t, dir, cf, map[string]string{"a.txt": "aaa"})

	writeFile(t, filepath.Join(dir, "b.txt"), "bbb")
	runScan(t, cf, dir, cf, 0, false, false)

	m, err := loadMD5(cf)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(m))
	}
	if m["./a.txt"] != knownMD5("aaa") {
		t.Error("a.txt mismatch after update")
	}
	if m["./b.txt"] != knownMD5("bbb") {
		t.Error("b.txt mismatch after update")
	}
}

// ── scan: mixed scenario ─────────────────────────────────────────────

func TestScanMixed(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	seedChecksums(t, dir, cf, map[string]string{
		"ok.txt":  "ok",
		"rot.txt": "rot",
		"mod.txt": "mod",
		"del.txt": "del",
	})

	writeFile(t, filepath.Join(dir, "rot.txt"), "ROTTED")
	ageFile(t, filepath.Join(dir, "rot.txt"), 10*time.Second)

	ageFile(t, cf, 10*time.Second)
	writeFile(t, filepath.Join(dir, "mod.txt"), "MODIFIED")

	os.Remove(filepath.Join(dir, "del.txt"))

	writeFile(t, filepath.Join(dir, "new.txt"), "new")

	bitrot, out := runScan(t, cf, dir, "", 0, true, false)

	if !bitrot {
		t.Error("should detect bitrot")
	}

	for _, want := range []string{
		"./ok.txt: OK",
		"./rot.txt: BAD",
		"./mod.txt: MOD",
		"./del.txt: DELETED",
		"./new.txt: NEW",
		"BIT ROT DETECTED",
		"MODIFIED",
		"DELETED",
		"NEW",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output", want)
		}
	}
}

// ── scan: parallel vs sequential consistency ─────────────────────────

func TestScanParallelMatchesSequential(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	writeFile(t, filepath.Join(dir, "a.txt"), "aaa")
	writeFile(t, filepath.Join(dir, "b.txt"), "bbb")
	writeFile(t, filepath.Join(dir, "c.txt"), "ccc")

	outDir := createTempDir(t)
	seqFile := filepath.Join(outDir, "seq.md5")
	parFile := filepath.Join(outDir, "par.md5")

	runScan(t, cf, dir, seqFile, 0, false, false)
	runScan(t, cf, dir, parFile, 4, false, false)

	seq, _ := loadMD5(seqFile)
	par, _ := loadMD5(parFile)

	if !reflect.DeepEqual(seq, par) {
		t.Errorf("sequential and parallel results differ:\n  seq: %v\n  par: %v", seq, par)
	}
}

// ── scan: unreadable file ────────────────────────────────────────────

func TestScanUnreadableFile(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping permission test when running as root")
	}

	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	seedChecksums(t, dir, cf, map[string]string{"a.txt": "aaa"})

	path := filepath.Join(dir, "a.txt")
	if err := os.Chmod(path, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
	})

	bitrot, out := runScan(t, cf, dir, "", 0, false, false)

	if !bitrot {
		t.Error("unreadable file should trigger problem flag")
	}
	if !strings.Contains(out, "ERRORS") {
		t.Errorf("expected ERRORS:\n%s", out)
	}
}

// ── scan: update file written correctly ──────────────────────────────

func TestScanUpdateDoesNotIncludeMD5Files(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, filepath.Join(dir, "a.txt"), "aaa")
	writeFile(t, filepath.Join(dir, "secret.md5"), "data")

	uf := filepath.Join(dir, "out.md5")
	runScan(t, "/dev/null", dir, uf, 0, false, false)

	m, err := loadMD5(uf)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 {
		t.Fatalf("expected 2 entries, got %d: %v", len(m), m)
	}
	if _, ok := m["./a.txt"]; !ok {
		t.Error("missing ./a.txt")
	}
	if _, ok := m["./secret.md5"]; !ok {
		t.Error("missing ./secret.md5 (it's a data file)")
	}
}

func TestScanUpdateDoesNotIncludeChecksumFile(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, filepath.Join(dir, "a.txt"), "aaa")

	cf := filepath.Join(dir, "c.md5")
	runScan(t, cf, dir, cf, 0, false, false)

	m, err := loadMD5(cf)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m["./c.md5"]; ok {
		t.Error("checksum file should not be in its own database")
	}
}

// ── scan: exit code semantics ────────────────────────────────────────

func TestScanExitCodeClean(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	seedChecksums(t, dir, cf, map[string]string{"a.txt": "aaa"})

	bitrot, _ := runScan(t, cf, dir, "", 0, false, false)
	if bitrot {
		t.Error("clean scan should return false")
	}
}

func TestScanExitCodeBitRot(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	seedChecksums(t, dir, cf, map[string]string{"a.txt": "aaa"})

	writeFile(t, filepath.Join(dir, "a.txt"), "CORRUPTED")
	ageFile(t, filepath.Join(dir, "a.txt"), 10*time.Second)

	bitrot, _ := runScan(t, cf, dir, "", 0, false, false)
	if !bitrot {
		t.Error("bitrot scan should return true")
	}
}

func TestScanExitCodeModifiedOnly(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	seedChecksums(t, dir, cf, map[string]string{"a.txt": "aaa"})

	ageFile(t, cf, 10*time.Second)
	writeFile(t, filepath.Join(dir, "a.txt"), "modified")

	bitrot, _ := runScan(t, cf, dir, "", 0, false, false)
	if bitrot {
		t.Error("modification only should return false (no bitrot)")
	}
}

func TestScanExitCodeDeletedOnly(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	seedChecksums(t, dir, cf, map[string]string{"a.txt": "aaa"})

	os.Remove(filepath.Join(dir, "a.txt"))

	bitrot, _ := runScan(t, cf, dir, "", 0, false, false)
	if bitrot {
		t.Error("deletion only should return false (no bitrot)")
	}
}

// ── scan: edge cases ─────────────────────────────────────────────────

func TestScanEmptyDirectory(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")

	bitrot, _ := runScan(t, cf, dir, cf, 0, false, false)
	if bitrot {
		t.Error("empty dir should not detect bitrot")
	}

	m, _ := loadMD5(cf)
	if len(m) != 0 {
		t.Errorf("expected 0 entries, got %d", len(m))
	}
}

func TestScanUnicodeFilenames(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	writeFile(t, filepath.Join(dir, "日本語.txt"), "nihongo")
	writeFile(t, filepath.Join(dir, "über.txt"), "uber")

	runScan(t, cf, dir, cf, 0, false, false)

	m, err := loadMD5(cf)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(m))
	}

	bitrot, _ := runScan(t, cf, dir, "", 0, false, false)
	if bitrot {
		t.Error("unicode filenames should round-trip cleanly")
	}
}

func TestScanDeepNesting(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	deep := filepath.Join(dir, "a", "b", "c", "d", "e", "f.txt")
	writeFile(t, deep, "deep")

	runScan(t, cf, dir, cf, 0, false, false)

	m, _ := loadMD5(cf)
	rel := "./a/b/c/d/e/f.txt"
	if _, ok := m[rel]; !ok {
		t.Errorf("missing %s, got: %v", rel, m)
	}
}

func TestScanHiddenDirsSkipped(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	writeFile(t, filepath.Join(dir, "a.txt"), "aaa")
	writeFile(t, filepath.Join(dir, ".git", "config"), "gitconfig")

	runScan(t, cf, dir, cf, 0, false, false)

	m, _ := loadMD5(cf)
	if len(m) != 1 {
		t.Fatalf("expected 1 entry (hidden dir skipped), got %d: %v", len(m), m)
	}
}

// ── knownMD5 consistency ─────────────────────────────────────────────

func TestKnownMD5Consistency(t *testing.T) {
	dir := createTempDir(t)
	path := filepath.Join(dir, "test.txt")
	writeFile(t, path, "verify consistency")

	buf := make([]byte, bufSize)
	fromFile, err := md5File(path, buf)
	if err != nil {
		t.Fatal(err)
	}
	fromHelper := knownMD5("verify consistency")

	if fromFile != fromHelper {
		t.Errorf("md5File=%s knownMD5=%s", fromFile, fromHelper)
	}
}

// ── resolveArgs ──────────────────────────────────────────────────────

func TestResolveArgs_DirectoryArg(t *testing.T) {
	dir := createTempDir(t)
	subdir := filepath.Join(dir, "mydata")
	if err := os.Mkdir(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	cf, uf, root := resolveArgs(subdir, true, false, false, "", "", "dummy")

	if cf != filepath.Join(subdir, "mydata.md5") {
		t.Errorf("cf = %s, want %s", cf, filepath.Join(subdir, "mydata.md5"))
	}
	if uf != "" {
		t.Errorf("uf = %q, want empty", uf)
	}
	if root != subdir {
		t.Errorf("root = %s, want %s", root, subdir)
	}
}

func TestResolveArgs_FileArg(t *testing.T) {
	dir := createTempDir(t)
	file := filepath.Join(dir, "snap.md5")
	writeFile(t, file, "")

	cf, uf, root := resolveArgs(file, true, false, false, "", "", "dummy")

	if cf != file {
		t.Errorf("cf = %s, want %s", cf, file)
	}
	if uf != "" {
		t.Errorf("uf = %q, want empty", uf)
	}
	if root != dir {
		t.Errorf("root = %s, want %s", root, dir)
	}
}

func TestResolveArgs_BareUpdateDefaultsToInputFile(t *testing.T) {
	dir := createTempDir(t)
	file := filepath.Join(dir, "snap.md5")

	cf, uf, root := resolveArgs(file, true, true, true, "", "", "dummy")

	if cf != file {
		t.Errorf("cf = %s, want %s", cf, file)
	}
	if uf != file {
		t.Errorf("uf = %s, want %s (should default to input, not CWD)", uf, file)
	}
	if root != dir {
		t.Errorf("root = %s, want %s", root, dir)
	}
}

func TestResolveArgs_BareUpdateWithDirArg(t *testing.T) {
	dir := createTempDir(t)
	subdir := filepath.Join(dir, "archive")
	if err := os.Mkdir(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	cf, uf, _ := resolveArgs(subdir, true, true, true, "", "", "dummy")

	expected := filepath.Join(subdir, "archive.md5")
	if cf != expected {
		t.Errorf("cf = %s, want %s", cf, expected)
	}
	if uf != expected {
		t.Errorf("uf = %s, want %s (bare -u should follow input, not CWD)", uf, expected)
	}
}

func TestResolveArgs_UpdateWithExplicitValue(t *testing.T) {
	dir := createTempDir(t)
	file := filepath.Join(dir, "input.md5")
	outFile := filepath.Join(dir, "output.md5")

	cf, uf, _ := resolveArgs(file, true, true, false, outFile, "", "dummy")

	if cf != file {
		t.Errorf("cf = %s, want %s", cf, file)
	}
	if uf != outFile {
		t.Errorf("uf = %s, want %s", uf, outFile)
	}
}

func TestResolveArgs_NoArgsNoUpdate(t *testing.T) {
	defaultName := "/cwd/mydata.md5"

	cf, uf, root := resolveArgs("", false, false, false, "", "", defaultName)

	if cf != defaultName {
		t.Errorf("cf = %s, want %s", cf, defaultName)
	}
	if uf != "" {
		t.Errorf("uf = %q, want empty", uf)
	}
	if root != "." {
		t.Errorf("root = %q, want %q", root, ".")
	}
}

func TestResolveArgs_UpdateNoPositional(t *testing.T) {
	cf, uf, root := resolveArgs("", false, true, false, "/out/file.md5", "", "dummy")

	if cf != "/dev/null" {
		t.Errorf("cf = %s, want /dev/null", cf)
	}
	if uf != "/out/file.md5" {
		t.Errorf("uf = %s, want /out/file.md5", uf)
	}
	if root != "." {
		t.Errorf("root = %q, want %q", root, ".")
	}
}

func TestResolveArgs_ExplicitRoot(t *testing.T) {
	dir := createTempDir(t)
	file := filepath.Join(dir, "snap.md5")

	cf, uf, root := resolveArgs(file, true, false, false, "", "/other", "dummy")

	if cf != file {
		t.Errorf("cf = %s, want %s", cf, file)
	}
	if uf != "" {
		t.Errorf("uf = %q, want empty", uf)
	}
	if root != "/other" {
		t.Errorf("root = %s, want /other", root)
	}
}

func TestDiscover_SkipsSymlinks(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, filepath.Join(dir, "real.txt"), "data")
	os.Symlink(filepath.Join(dir, "real.txt"), filepath.Join(dir, "link.txt"))

	files, err := discover(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d: %v", len(files), keysOf(files))
	}
	if _, ok := files["./real.txt"]; !ok {
		t.Error("missing ./real.txt")
	}
}

func TestDiscover_SkipsFIFO(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, filepath.Join(dir, "real.txt"), "data")
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0644); err != nil {
		t.Fatal(err)
	}

	files, err := discover(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d: %v", len(files), keysOf(files))
	}
	if _, ok := files["./real.txt"]; !ok {
		t.Error("missing ./real.txt")
	}
}

func TestValidateChecksumFile_MissingNoUpdate(t *testing.T) {
	err := validateChecksumFile("/nonexistent/file.md5", false)
	if err == nil {
		t.Error("expected error for non-existent file without --update")
	}
}

func TestValidateChecksumFile_MissingWithUpdate(t *testing.T) {
	err := validateChecksumFile("/nonexistent/file.md5", true)
	if err != nil {
		t.Errorf("expected no error with --update, got: %v", err)
	}
}

func TestValidateChecksumFile_Exists(t *testing.T) {
	dir := createTempDir(t)
	path := filepath.Join(dir, "test.md5")
	writeFile(t, path, "")

	err := validateChecksumFile(path, false)
	if err != nil {
		t.Errorf("expected no error for existing file, got: %v", err)
	}
}

func TestScanTempFileWhenNewsNoUpdate(t *testing.T) {
	dir := createTempDir(t)
	cf := filepath.Join(dir, "c.md5")
	seedChecksums(t, dir, cf, map[string]string{"a.txt": "aaa"})

	writeFile(t, filepath.Join(dir, "b.txt"), "bbb")

	_, out := runScan(t, cf, dir, "", 0, false, false)

	if !strings.Contains(out, "Checksums saved to") {
		t.Fatalf("expected temp file message:\n%s", out)
	}

	// Extract temp file path from output.
	lines := strings.Split(out, "\n")
	var tmpPath string
	for _, line := range lines {
		if strings.Contains(line, "Checksums saved to") {
			parts := strings.SplitN(line, " ", 4)
			if len(parts) >= 4 {
				tmpPath = strings.TrimSpace(parts[3])
			}
		}
	}
	if tmpPath == "" {
		t.Fatal("could not extract temp file path from output")
	}

	// Verify it exists and contains valid checksums.
	m, err := loadMD5(tmpPath)
	if err != nil {
		t.Fatalf("temp file unreadable: %v", err)
	}
	if len(m) != 2 {
		t.Fatalf("expected 2 entries in temp file, got %d", len(m))
	}
	os.Remove(tmpPath)
}
