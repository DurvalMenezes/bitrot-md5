package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const bufSize = 64 << 10

// ── Types ────────────────────────────────────────────────────────────

type fileEntry struct {
	abs   string
	mtime time.Time
}

type hashRes struct {
	rel  string
	hash string
	err  error
}

type change struct {
	path, saved, actual string
}

type ferr struct {
	p, m string
}

type scanResult struct {
	newDB    map[string]string
	bitrot   []change
	modified []change
	added    []change
	deleted  []string
	errs     []ferr
	statuses map[string]string
	problem  bool
}

func (r scanResult) hasNews() bool {
	return r.problem || len(r.modified) > 0 || len(r.deleted) > 0 || len(r.added) > 0
}

type optionalInt struct {
	value      int
	isSet      bool
	defaultVal int
}

func (o *optionalInt) String() string {
	if o.isSet {
		return strconv.Itoa(o.value)
	}
	return "0"
}

func (o *optionalInt) Set(s string) error {
	o.isSet = true
	if s == "true" {
		o.value = o.defaultVal
		return nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("invalid integer: %s", s)
	}
	o.value = v
	return nil
}

func (o *optionalInt) IsBoolFlag() bool { return true }

type optionalString struct {
	value string
	isSet bool
}

func (o *optionalString) String() string { return o.value }

func (o *optionalString) Set(s string) error {
	o.isSet = true
	if s == "true" {
		o.value = ""
	} else {
		o.value = s
	}
	return nil
}

func (o *optionalString) IsBoolFlag() bool { return true }

// ── Argument preprocessing ───────────────────────────────────────────

func normalizeArgs() {
	takesValue := map[string]bool{
		"root": true, "r": true,
		"update": true, "u": true,
	}

	var flags []string
	var positional []string

	args := os.Args[1:]
	i := 0
	for i < len(args) {
		arg := args[i]

		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}

		if !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			i++
			continue
		}

		normalized := arg
		if strings.HasPrefix(arg, "--") {
			normalized = "-" + arg[2:]
		}

		trimmed := strings.TrimLeft(normalized, "-")
		name := trimmed
		if idx := strings.Index(trimmed, "="); idx >= 0 {
			name = trimmed[:idx]
		}

		flags = append(flags, normalized)
		i++

		if takesValue[name] && !strings.Contains(arg, "=") && i < len(args) {
			flags = append(flags, args[i])
			i++
		}
	}

	var out []string
	out = append(out, os.Args[0])
	out = append(out, flags...)
	out = append(out, positional...)
	os.Args = out
}

// ── Argument resolution ──────────────────────────────────────────────

func resolveArgs(cfArg string, hasPositional bool, hasUpdate, isBareUpdate bool, updateValue, optRoot, defaultName string) (cf, uf, root string) {
	if hasPositional {
		if info, err := os.Stat(cfArg); err == nil && info.IsDir() {
			cf = filepath.Join(cfArg, filepath.Base(cfArg)+".md5")
		} else {
			cf = cfArg
		}
	} else if hasUpdate {
		cf = "/dev/null"
	} else {
		cf = defaultName
	}

	if isBareUpdate {
		uf = cf
	} else if hasUpdate {
		uf = updateValue
	}

	root = optRoot
	if root == "" {
		if hasPositional {
			root = filepath.Dir(cf)
		} else {
			root = "."
		}
	}

	return cf, uf, root
}

// ── Main ─────────────────────────────────────────────────────────────

func main() {
	normalizeArgs()

	var optRoot string
	var verbose bool
	var summary bool

	flag.StringVar(&optRoot, "root", "",
		"directory to scan (default: current directory or dirname of checksum file)")
	flag.StringVar(&optRoot, "r", "",
		"short for --root")
	optUpdate := &optionalString{}
	flag.Var(optUpdate, "update",
		"write updated checksums to this file (bare -u: use DIRNAME.md5)")
	flag.Var(optUpdate, "u",
		"short for --update")
	workers := &optionalInt{defaultVal: runtime.NumCPU()}
	flag.Var(workers, "parallel",
		"parallel hashing with N workers (bare --parallel = NumCPU)")
	flag.Var(workers, "p",
		"short for --parallel")
	flag.BoolVar(&verbose, "verbose", false,
		"show per-file verification status and preamble")
	flag.BoolVar(&verbose, "v", false,
		"short for --verbose")
	flag.BoolVar(&summary, "summary", false,
		"show scan preamble and summary even when all files are OK")
	flag.BoolVar(&summary, "s", false,
		"short for --summary")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] [CHECKSUM_FILE]\n\n"+
				"Detect bit rot using a standard md5sum-compatible checksum file.\n\n"+
				"If a file's hash differs from the saved value:\n"+
				"  file mtime ≤ checksum file mtime  →  CORRUPTED (bit rot)\n"+
				"  file mtime > checksum file mtime  →  MODIFIED  (intentional edit)\n\n"+
				"Defaults:\n"+
				"  No CHECKSUM_FILE and no --update:  use DIRNAME.md5\n"+
				"  No CHECKSUM_FILE but --update:     use /dev/null (first run)\n"+
				"  Bare --update (no value):          write to DIRNAME.md5\n\n"+
				"By default, if nothing is changed or wrong, nothing is printed (exit 0).\n"+
				"Use --summary or --verbose to see scan details even when all is OK.\n\n"+
				"Options:\n"+
				"  -p, --parallel [N]  Parallel hashing (bare = NumCPU, default: sequential)\n"+
				"  -r, --root DIR      Directory to scan (default: current directory)\n"+
				"  -s, --summary       Show scan preamble and summary\n"+
				"  -u, --update FILE   Write updated checksums to this file\n"+
				"  -v, --verbose       Show per-file verification status\n"+
				"  -h, --help          Show this help\n",
			os.Args[0])
	}
	flag.Parse()

	cwd, err := os.Getwd()
	if err != nil {
		die("cannot determine current directory: %v", err)
	}
	defaultName := "./" + filepath.Base(cwd) + ".md5"

	hasUpdate := optUpdate.isSet
	isBareUpdate := hasUpdate && optUpdate.value == ""

	cf, uf, rootDir := resolveArgs(
		mustAbs(flag.Arg(0)), flag.NArg() == 1,
		hasUpdate, isBareUpdate, optUpdate.value, optRoot, defaultName,
	)
	cf = mustAbs(cf)
	if uf != "" {
		uf = mustAbs(uf)
	}
	rd := mustAbs(rootDir)

	if err := validateChecksumFile(cf, uf != ""); err != nil {
		die("%v", err)
	}

	if workers.value < 0 {
		die("--parallel value must be non-negative")
	}

	nw := 0
	if workers.isSet {
		nw = workers.value
	}

	rot, err := scan(cf, rd, uf, nw, verbose, summary)
	if err != nil {
		die("%v", err)
	}
	if rot {
		os.Exit(1)
	}
}

func validateChecksumFile(cf string, hasUpdate bool) error {
	if _, err := os.Stat(cf); os.IsNotExist(err) && !hasUpdate {
		return fmt.Errorf("checksum file not found: %s (use --update to create it)", cf)
	}
		return nil
}

// ── Core logic ───────────────────────────────────────────────────────

func scan(cf, rootDir, uf string, workers int, verbose, summary bool) (bool, error) {
	showDetail := verbose || summary

	old, lastScan, err := loadAndCleanChecksums(cf, rootDir, uf)
	if err != nil {
		return false, err
	}

	if showDetail && len(old) > 0 {
		printPreamble(lastScan, len(old))
	}

	skip := map[string]bool{cf: true}
	if uf != "" {
		skip[uf] = true
	}
	cur, err := discover(rootDir, skip)
	if err != nil {
		return false, fmt.Errorf("scanning %s: %w", rootDir, err)
	}

	deleted := findDeleted(old, cur)
	results := hashAll(cur, workers)
	r := classifyChanges(old, cur, results, lastScan, verbose, deleted)

	if verbose {
		printVerboseStatuses(r.statuses)
	}
	printSummary(r, len(old) > 0, len(r.newDB), showDetail)

	return r.problem, persistResults(uf, r.newDB, showDetail, r.hasNews())
}

func loadAndCleanChecksums(cf, rootDir, uf string) (map[string]string, time.Time, error) {
	old, err := loadMD5(cf)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("reading %s: %w", cf, err)
	}

	var lastScan time.Time
	if len(old) > 0 {
		if fi, err := os.Stat(cf); err == nil {
			lastScan = fi.ModTime()
		}
	}

	cfRel, _ := filepath.Rel(rootDir, cf)
	delete(old, "./"+filepath.ToSlash(cfRel))
	if uf != "" {
		ufRel, _ := filepath.Rel(rootDir, uf)
		delete(old, "./"+filepath.ToSlash(ufRel))
	}

	return old, lastScan, nil
}

func printPreamble(lastScan time.Time, entryCount int) {
	if !lastScan.IsZero() {
		fmt.Printf("Last scan : %s\n", lastScan.Format("2006-01-02 15:04:05"))
	}
	fmt.Printf("Entries   : %d\n", entryCount)
}

func findDeleted(old map[string]string, cur map[string]fileEntry) []string {
	var deleted []string
	for p := range old {
		if _, ok := cur[p]; !ok {
			deleted = append(deleted, p)
		}
	}
	sort.Strings(deleted)
	return deleted
}

func classifyChanges(old map[string]string, cur map[string]fileEntry, results []hashRes, lastScan time.Time, verbose bool, deleted []string) scanResult {
	r := scanResult{
		newDB:    make(map[string]string, len(cur)),
		statuses: make(map[string]string),
		deleted:  deleted,
	}

	for _, res := range results {
		if res.err != nil {
			r.errs = append(r.errs, ferr{res.rel, res.err.Error()})
			r.problem = true
			if verbose {
				r.statuses[res.rel] = "ERROR"
			}
			continue
		}
		r.newDB[res.rel] = res.hash

		prev, existed := old[res.rel]
		if !existed {
			r.added = append(r.added, change{res.rel, "", res.hash})
			if verbose {
				r.statuses[res.rel] = "NEW"
			}
			continue
		}
		if prev == res.hash {
			if verbose {
				r.statuses[res.rel] = "OK"
			}
			continue
		}
		if cur[res.rel].mtime.After(lastScan) {
			r.modified = append(r.modified, change{res.rel, prev, res.hash})
			if verbose {
				r.statuses[res.rel] = "MOD"
			}
		} else {
			r.bitrot = append(r.bitrot, change{res.rel, prev, res.hash})
			r.problem = true
			if verbose {
				r.statuses[res.rel] = "BAD"
			}
		}
	}

	for _, p := range deleted {
		if verbose {
			r.statuses[p] = "DELETED"
		}
	}

	return r
}

func printVerboseStatuses(statuses map[string]string) {
	if len(statuses) == 0 {
		return
	}
	keys := make([]string, 0, len(statuses))
	for k := range statuses {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("%s: %s\n", k, statuses[k])
	}
	fmt.Println()
}

func printSummary(r scanResult, hasOld bool, newDBCount int, showDetail bool) {
	show := func(label string, items []change) {
		fmt.Printf("%s (%d):\n", label, len(items))
		for _, c := range items {
			fmt.Printf("  %s\n    saved:  %s\n    actual: %s\n",
				c.path, c.saved, c.actual)
		}
	}

	if len(r.bitrot) > 0 {
		show("BIT ROT DETECTED", r.bitrot)
	}
	if len(r.modified) > 0 {
		if len(r.bitrot) > 0 {
			fmt.Println()
		}
		show("MODIFIED", r.modified)
	}
	if len(r.deleted) > 0 {
		fmt.Printf("\nDELETED (%d):\n", len(r.deleted))
		for _, p := range r.deleted {
			fmt.Printf("  %s\n", p)
		}
	}
	if len(r.added) > 0 {
		fmt.Printf("\nNEW (%d):\n", len(r.added))
		for _, c := range r.added {
			fmt.Printf("  %s\n", c.path)
		}
	}
	if len(r.errs) > 0 {
		fmt.Printf("\nERRORS (%d):\n", len(r.errs))
		for _, e := range r.errs {
			fmt.Printf("  %s: %s\n", e.p, e.m)
		}
	}

	if !r.hasNews() && showDetail {
		if hasOld {
			fmt.Println("\nAll files OK — no bit rot detected.")
		} else {
			fmt.Printf("\nFirst run — indexed %d files.\n", newDBCount)
		}
	}
}

func persistResults(uf string, newDB map[string]string, showDetail, hasNews bool) error {
	if uf != "" {
		if err := saveMD5(uf, newDB); err != nil {
			return fmt.Errorf("writing %s: %w", uf, err)
		}
		if showDetail || hasNews {
			fmt.Printf("\nWrote %d entries to %s\n", len(newDB), uf)
		}
	} else if hasNews {
		tmp, err := os.CreateTemp("", "bitrot-md5-*.md5")
		if err != nil {
			return fmt.Errorf("creating temp file: %w", err)
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		if err := saveMD5(tmp.Name(), newDB); err != nil {
			return fmt.Errorf("writing temp file: %w", err)
		}
		fmt.Printf("\nChecksums saved to %s\n  Verify and apply: mv %s CHECKSUM_FILE\n", tmp.Name(), tmp.Name())
	}
	return nil
}

// ── md5sum file I/O ──────────────────────────────────────────────────

func loadMD5(path string) (map[string]string, error) {
	m := make(map[string]string)
	if path == "/dev/null" {
		return m, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return m, nil
		}
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	ln := 0
	for sc.Scan() {
		ln++
		h, p, ok := parseLine(sc.Text())
		if !ok {
			fmt.Fprintf(os.Stderr,
				"WARNING: malformed line %d in %s, skipping\n", ln, path)
			continue
		}
		m[p] = h
	}
	return m, sc.Err()
}

func parseLine(line string) (hash, fpath string, ok bool) {
	if line == "" {
		return "", "", false
	}
	if i := strings.Index(line, "  "); i > 0 {
		return line[:i], strings.TrimPrefix(line[i+2:], "*"), true
	}
	if i := strings.Index(line, " "); i > 0 {
		return line[:i], strings.TrimPrefix(line[i+1:], "*"), true
	}
	return "", "", false
}

func saveMD5(path string, db map[string]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	keys := make([]string, 0, len(db))
	for k := range db {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	w := bufio.NewWriter(f)
	for _, k := range keys {
		fmt.Fprintf(w, "%s  %s\n", db[k], k)
	}
	return w.Flush()
}

// ── File discovery ───────────────────────────────────────────────────

func discover(root string, skip map[string]bool) (map[string]fileEntry, error) {
	out := make(map[string]fileEntry)
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if p == root {
				return err
			}
			fmt.Fprintf(os.Stderr, "WARNING: %v\n", err)
			return nil
		}
		if d.IsDir() {
			if p != root && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if skip[p] {
			return nil
		}
		if d.Type()&os.ModeType != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: %v\n", err)
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		out["./"+filepath.ToSlash(rel)] = fileEntry{
			abs:   p,
			mtime: info.ModTime(),
		}
		return nil
	})
	return out, err
}

// ── Hashing ──────────────────────────────────────────────────────────

func hashAll(files map[string]fileEntry, workers int) []hashRes {
	if workers > 0 {
		return hashParallel(files, workers)
	}
	return hashSequential(files)
}

func hashSequential(files map[string]fileEntry) []hashRes {
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	buf := make([]byte, bufSize)
	all := make([]hashRes, 0, len(files))
	for _, k := range keys {
		h, err := md5File(files[k].abs, buf)
		all = append(all, hashRes{k, h, err})
	}
	return all
}

func hashParallel(files map[string]fileEntry, nw int) []hashRes {
	type job struct{ rel, abs string }
	jobs := make(chan job, nw)
	out := make(chan hashRes, len(files))

	var wg sync.WaitGroup
	for i := 0; i < nw; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, bufSize)
			for j := range jobs {
				h, err := md5File(j.abs, buf)
				out <- hashRes{j.rel, h, err}
			}
		}()
	}

	go func() {
		for rel, e := range files {
			jobs <- job{rel, e.abs}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	all := make([]hashRes, 0, len(files))
	for r := range out {
		all = append(all, r)
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].rel < all[j].rel
	})
	return all
}

func md5File(path string, buf []byte) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ── Helpers ──────────────────────────────────────────────────────────

func mustAbs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		die("%v", err)
	}
	return a
}

func die(f string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: "+f+"\n", a...)
	os.Exit(1)
}
