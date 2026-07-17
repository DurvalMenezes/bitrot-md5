package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
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

// Exit code flag bits.
const (
	exitProblem = 1 // bit rot or file access errors detected
	exitUsage   = 15
	exitPartial = 16 // --max-time exceeded
	exitRandom  = 32 // --random-order, filesystem scan skipped
)

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

type scanConfig struct {
	rootDir         string
	checksumIn      string
	checksumOut     string
	workers         int
	verbose         bool
	summary         bool
	randomOrder     bool
	maxTime         time.Duration
	totalFilesInOld int
}

type timeBudgetExceededError struct{}

func (e *timeBudgetExceededError) Error() string {
	return "time budget exceeded"
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
	requiresValue := map[string]bool{
		"root": true, "r": true,
		"update": true, "u": true,
		"max-time": true, "m": true,
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

		if requiresValue[name] && !strings.Contains(arg, "=") &&
			i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			flags = append(flags, normalized+"="+args[i+1])
			i += 2
			continue
		}

		flags = append(flags, normalized)
		i++
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

func validateChecksumFile(cf string, hasUpdate bool) error {
	if _, err := os.Stat(cf); os.IsNotExist(err) && !hasUpdate {
		return fmt.Errorf("checksum file not found: %s (use --update to create it)", cf)
	}
	return nil
}

// ── Main ─────────────────────────────────────────────────────────────

func main() {
	normalizeArgs()

	var optRoot string
	var verbose bool
	var summary bool
	var randomOrder bool
	var optMaxTime string

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
	flag.StringVar(&optMaxTime, "max-time", "",
		"verify: time budget (e.g. 30m, 1h). Partial run if exceeded")
	flag.StringVar(&optMaxTime, "m", "",
		"short for --max-time")
	flag.BoolVar(&randomOrder, "random-order", false,
		"verify: randomized file order, skip filesystem scan for new files")
	flag.BoolVar(&randomOrder, "R", false,
		"short for --random-order")

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
				"  -m, --max-time DUR  Time budget for verify (e.g. 30m, 1h, 45s)\n"+
				"  -p, --parallel [N]  Parallel hashing (bare = NumCPU, default: sequential)\n"+
				"  -R, --random-order  Randomized file order, skip filesystem scan\n"+
				"  -r, --root DIR      Directory to scan (default: current directory)\n"+
				"  -s, --summary       Show scan preamble and summary\n"+
				"  -u, --update FILE   Write updated checksums to this file\n"+
				"  -v, --verbose       Show per-file verification status\n"+
				"  -h, --help          Show this help\n\n"+
				"Exit codes (bitwise flags):\n"+
				"   0  OK — no issues\n"+
				"   1  Problems detected: Bit rot and/or file access errors\n"+
				"  15  Usage error\n"+
				"  16  Partial run (--max-time exceeded), no problems\n"+
				"  17  Partial run (--max-time exceeded), problems detected\n"+
				"  32  Random-order run (filesystem scan skipped), no problems\n"+
				"  33  Random-order run (filesystem scan skipped), problems detected\n"+
				"  48  Partial + random-order run, no problems\n"+
				"  49  Partial + random-order run, problems detected\n",
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

	if randomOrder && hasUpdate {
		die("--random-order and --update/-u are mutually exclusive")
	}

	var maxTime time.Duration
	if optMaxTime != "" {
		maxTime, err = time.ParseDuration(optMaxTime)
		if err != nil {
			die("invalid --max-time value: %v", err)
		}
		if maxTime <= 0 {
			die("--max-time must be positive")
		}
	}

	if workers.value < 0 {
		die("--parallel value must be non-negative")
	}

	nw := 0
	if workers.isSet {
		nw = workers.value
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := scanConfig{
		rootDir:         rd,
		checksumIn:      cf,
		checksumOut:     uf,
		workers:         nw,
		verbose:         verbose,
		summary:         summary,
		randomOrder:     randomOrder,
		maxTime:         maxTime,
		totalFilesInOld: -1,
	}

	bitrot, scanErr := scan(ctx, cfg)
	var timeErr2 *timeBudgetExceededError
	if scanErr != nil && !errors.As(scanErr, &timeErr2) {
		die("%v", scanErr)
	}

	// Bitwise exit code composition.
	exitCode := 0
	if bitrot {
		exitCode |= exitProblem
	}
	var timeErr *timeBudgetExceededError
	if errors.As(scanErr, &timeErr) {
		exitCode |= exitPartial
	}
	if cfg.randomOrder {
		exitCode |= exitRandom
	}

	os.Exit(exitCode)
}

// ── Core logic ───────────────────────────────────────────────────────

func scan(ctx context.Context, cfg scanConfig) (bool, error) {
	showDetail := cfg.verbose || cfg.summary

	old, lastScan, err := loadAndCleanChecksums(cfg.checksumIn, cfg.rootDir, cfg.checksumOut)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", cfg.checksumIn, err)
	}

	if showDetail && len(old) > 0 {
		printPreamble(lastScan, len(old))
	}

	var cur map[string]fileEntry
	var deleted []string

	if cfg.randomOrder {
		cur, deleted = buildFromManifest(old, cfg.rootDir)
	} else {
		skip := map[string]bool{cfg.checksumIn: true}
		if cfg.checksumOut != "" {
			skip[cfg.checksumOut] = true
		}
		cur, err = discover(cfg.rootDir, skip)
		if err != nil {
			return false, fmt.Errorf("scanning %s: %w", cfg.rootDir, err)
		}
		deleted = findDeleted(old, cur)
	}

	totalFiles := len(cur) + len(deleted)

	applyBudget := cfg.maxTime > 0 && (cfg.randomOrder || cfg.checksumOut == "")
	tCtx := ctx
	var tCancel context.CancelFunc = func() {}
	if applyBudget {
		tCtx, tCancel = context.WithTimeout(ctx, cfg.maxTime)
	}
	defer tCancel()

	var results []hashRes
	if cfg.randomOrder {
		if cfg.workers > 0 {
			results = hashShuffledParallel(tCtx, cur, cfg.workers)
		} else {
			results = hashShuffledSequential(tCtx, cur)
		}
	} else if applyBudget && cfg.workers > 0 {
		results = hashParallelTimed(tCtx, cur, cfg.workers)
	} else if applyBudget {
		results = hashSequentialTimed(tCtx, cur)
	} else if cfg.workers > 0 {
		results = hashParallel(cur, cfg.workers)
	} else {
		results = hashSequential(cur)
	}

	r := classifyChanges(old, cur, results, lastScan, cfg.verbose, deleted)

	if cfg.verbose {
		printVerboseStatuses(r.statuses)
	}

	checked := len(results)
	timedOut := applyBudget && tCtx.Err() != nil && checked < totalFiles

	printSummary(r, len(old) > 0, len(r.newDB), showDetail, timedOut, checked, totalFiles, cfg.maxTime)

	if cfg.randomOrder {
		fmt.Fprintln(os.Stderr,
			"WARNING: --random-order set, NOT scanning the filesystem for new files")
	}

	if cfg.checksumOut != "" {
		if err := saveMD5(cfg.checksumOut, r.newDB); err != nil {
			return false, fmt.Errorf("writing %s: %w", cfg.checksumOut, err)
		}
		if showDetail || r.hasNews() {
			fmt.Printf("Wrote %d entries to %s\n", len(r.newDB), cfg.checksumOut)
		}
	} else if r.hasNews() {
		if timedOut {
			fmt.Fprintf(os.Stderr,
				"WARNING: run was partial (--max-time exceeded); "+
					"NOT writing incomplete checksums to a temp file.\n"+
					"  Checked %d of %d files. Re-run without --max-time for a full pass.\n",
				checked, totalFiles)
		} else {
			tmp, tmpErr := os.CreateTemp("", "bitrot-md5-*.md5")
			if tmpErr != nil {
				return false, fmt.Errorf("creating temp file: %w", tmpErr)
			}
			if tmpErr := tmp.Close(); tmpErr != nil {
				return false, tmpErr
			}
			if tmpErr := saveMD5(tmp.Name(), r.newDB); tmpErr != nil {
				return false, fmt.Errorf("writing temp file: %w", tmpErr)
			}
			fmt.Printf("Checksums saved to %s\n  Verify and apply: mv %s CHECKSUM_FILE\n",
				tmp.Name(), tmp.Name())
		}
	}

	if timedOut {
		return r.problem, &timeBudgetExceededError{}
	}
	return r.problem, nil
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

func buildFromManifest(old map[string]string, rootDir string) (map[string]fileEntry, []string) {
	cur := make(map[string]fileEntry, len(old))
	var deleted []string

	for rel := range old {
		abs := filepath.Join(rootDir, rel)
		if info, err := os.Stat(abs); err == nil {
			cur[rel] = fileEntry{
				abs:   abs,
				mtime: info.ModTime(),
			}
		} else {
			deleted = append(deleted, rel)
		}
	}
	sort.Strings(deleted)
	return cur, deleted
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
			if os.IsNotExist(res.err) {
				if _, inOld := old[res.rel]; inOld {
					if verbose {
						r.statuses[res.rel] = "DELETED"
					}
					continue
				}
			}
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

func printSummary(r scanResult, hasOld bool, newDBCount int, showDetail bool, timedOut bool, checked, totalFiles int, maxTime time.Duration) {
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
		fmt.Printf("DELETED (%d):\n", len(r.deleted))
		for _, p := range r.deleted {
			fmt.Printf("  %s\n", p)
		}
	}
	if len(r.added) > 0 {
		fmt.Printf("NEW (%d):\n", len(r.added))
		for _, c := range r.added {
			fmt.Printf("  %s\n", c.path)
		}
	}
	if len(r.errs) > 0 {
		fmt.Printf("ERRORS (%d):\n", len(r.errs))
		for _, e := range r.errs {
			fmt.Printf("  %s: %s\n", e.p, e.m)
		}
	}

	if timedOut {
		fmt.Printf("PARTIAL: checked %d of %d files (--max-time '%s' exceeded)\n",
			checked, totalFiles, maxTime)
	} else if !r.hasNews() && showDetail {
		if hasOld {
			fmt.Println("All files OK — no bit rot detected.")
		} else {
			fmt.Printf("First run — indexed %d files.\n", newDBCount)
		}
	}
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
	escaped := false
	if strings.HasPrefix(line, "\\") {
		escaped = true
		line = line[1:]
	}

	var p string
	if i := strings.Index(line, "  "); i > 0 {
		hash, p = line[:i], strings.TrimPrefix(line[i+2:], "*")
	} else if i := strings.Index(line, " "); i > 0 {
		hash, p = line[:i], strings.TrimPrefix(line[i+1:], "*")
	} else {
		return "", "", false
	}
	if escaped {
		p = strings.ReplaceAll(p, "\\n", "\n")
		p = strings.ReplaceAll(p, "\\\\", "\\")
	}
	return hash, p, true
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
	out := make(chan hashRes, nw)

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

func shuffle(files []hashReq) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := len(files) - 1; i > 0; i-- {
		j := r.Intn(i + 1)
		files[i], files[j] = files[j], files[i]
	}
}

func hashShuffledSequential(ctx context.Context, files map[string]fileEntry) []hashRes {
	reqs := make([]hashReq, 0, len(files))
	for rel, e := range files {
		reqs = append(reqs, hashReq{rel, e.abs})
	}
	shuffle(reqs)

	buf := make([]byte, bufSize)
	all := make([]hashRes, 0, len(reqs))
	for _, req := range reqs {
		if ctx.Err() != nil {
			break
		}
		h, err := md5File(req.abs, buf)
		all = append(all, hashRes{req.rel, h, err})
	}
	return all
}

func hashShuffledParallel(ctx context.Context, files map[string]fileEntry, nw int) []hashRes {
	reqs := make([]hashReq, 0, len(files))
	for rel, e := range files {
		reqs = append(reqs, hashReq{rel, e.abs})
	}
	shuffle(reqs)

	type job struct{ rel, abs string }
	jobs := make(chan job, nw)
	out := make(chan hashRes, nw)

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
		for _, req := range reqs {
			if ctx.Err() != nil {
				break
			}
			jobs <- job(req)
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

func hashSequentialTimed(ctx context.Context, files map[string]fileEntry) []hashRes {
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	buf := make([]byte, bufSize)
	all := make([]hashRes, 0, len(files))
	for _, k := range keys {
		if ctx.Err() != nil {
			break
		}
		h, err := md5File(files[k].abs, buf)
		all = append(all, hashRes{k, h, err})
	}
	return all
}

func hashParallelTimed(ctx context.Context, files map[string]fileEntry, nw int) []hashRes {
	type job struct{ rel, abs string }

	reqs := make([]hashReq, 0, len(files))
	for rel, e := range files {
		reqs = append(reqs, hashReq{rel, e.abs})
	}

	jobs := make(chan job, nw)
	out := make(chan hashRes, nw)

	var wg sync.WaitGroup
	for i := 0; i < nw; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, bufSize)
			for {
				select {
				case <-ctx.Done():
					return
				case j, ok := <-jobs:
					if !ok {
						return
					}
					h, err := md5File(j.abs, buf)
					out <- hashRes{j.rel, h, err}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, req := range reqs {
			select {
			case <-ctx.Done():
				return
			case jobs <- job(req):
			}
		}
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

type hashReq struct {
	rel string
	abs string
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
	os.Exit(exitUsage)
}
