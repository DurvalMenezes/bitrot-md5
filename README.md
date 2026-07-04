# bitrot-md5

Detect silent data corruption (bit rot) using standard `md5sum`-compatible checksum files.

Inspired by [marcopaganini/bitrot](https://github.com/marcopaganini/bitrot), but stores checksums in a plain-text `.md5` file instead of a SQLite database. The file is directly readable and verifiable with `md5sum -c`.

## How it works

bitrot-md5 computes the MD5 hash of every file in a directory tree and compares it against a saved checksum file. When a hash doesn't match, the tool distinguishes between two causes:

| File mtime vs. checksum file mtime | Meaning |
|---|---|
| mtime **≤** last scan | **Bit rot** — silent corruption (the file changed but nobody touched it) |
| mtime **>** last scan | **Modified** — someone intentionally edited the file |

The checksum file mtime serves as the "last known good" timestamp. No per-file timestamps are stored — just paths and hashes, in standard `md5sum` format (hash, two spaces, relative path, one entry per line).

## Install

    go build -o bitrot-md5 .

Produces a single static binary. No runtime dependencies.

Cross-compile:

    GOOS=linux GOARCH=arm64 go build -o bitrot-md5-arm64 .
    GOOS=windows GOARCH=amd64 go build -o bitrot-md5.exe .

## Quick start

    # First run — index all files in the current directory
    bitrot-md5 -u

    # Later — check for corruption (silent if all OK, exits 0)
    bitrot-md5

    # Verbose — show per-file status
    bitrot-md5 -v

    # Check a specific directory
    bitrot-md5 -u /mnt/backup/backup.md5 /mnt/backup

## Usage

    bitrot-md5 [options] [CHECKSUM_FILE]

### Defaults

When run with no arguments from `/path/to/mydata/`:

- **Scans** the current directory
- **Reads** `./mydata.md5` (derived from the directory name)
- **Writes** nothing unless `--update` is given
- **Prints** nothing if all files are OK (exit 0)

| Scenario | Checksum file (input) | Root directory | Checksum file (output) |
|---|---|---|---|
| `bitrot-md5` | `./DIRNAME.md5` | `.` | *(none)* |
| `bitrot-md5 -u` | `./DIRNAME.md5` | `.` | `./DIRNAME.md5` |
| `bitrot-md5 -u backup.md5` | `/dev/null` | `.` | `./backup.md5` |
| `bitrot-md5 /bak/snap.md5` | `/bak/snap.md5` | `/bak/` | *(none)* |
| `bitrot-md5 -v /bak/snap.md5` | `/bak/snap.md5` | `/bak/` | *(none)* |

### Options

| Short | Long | Description |
|---|---|---|
| `-p [N]` | `--parallel [N]` | Parallel hashing with N workers. Bare `--parallel` uses all CPUs. Default: sequential. |
| `-r DIR` | `--root DIR` | Directory to scan. Default: current directory, or `dirname` of checksum file if specified. |
| `-s` | `--summary` | Show scan preamble (last scan time, entry count) and summary even when all is OK. |
| `-u [FILE]` | `--update [FILE]` | Write updated checksums to FILE. Bare `-u` writes to `./DIRNAME.md5`. |
| `-v` | `--verbose` | Show per-file verification status. Implies `--summary`. |
| `-h` | `--help` | Show help. |

Arguments are position-free: `bitrot-md5 -u=out.md5 input.md5` is the same as `bitrot-md5 input.md5 -u=out.md5`. The `=` sign is optional: `-u out.md5` works the same as `-u=out.md5`.

### Parallel hashing

By default, files are hashed sequentially — safe for spinning disks where concurrent reads cause seek thrashing.

For SSDs, NVMe drives, or network mounts, enable parallel hashing:

    bitrot-md5 -p -u        # auto-detect CPU count
    bitrot-md5 -p4 -u       # 4 workers
    bitrot-md5 --parallel=8 -u

### Verbose output

With `-v`, each file is printed on its own line with a status tag:

    ./photos/2024/img001.jpg: OK
    ./photos/2024/img002.jpg: BAD
    ./documents/report.pdf: MOD
    ./documents/new.txt: NEW
    ./old/deleted.txt: DELETED

Status tags:

| Tag | Meaning |
|---|---|
| `OK` | Hash matches saved value |
| `BAD` | Hash changed, mtime older than checksum file (bit rot) |
| `MOD` | Hash changed, mtime newer than checksum file (intentional edit) |
| `NEW` | File not in previous checksum file |
| `DELETED` | File was in previous checksum file but no longer exists |
| `ERROR` | File could not be read |

## Checksum file format

Standard `md5sum` output format — no proprietary database. Verify manually:

    cd /mnt/backup && md5sum -c backup.md5

Generate with standard tools (bitrot-md5 produces identical output):

    cd /mnt/backup && find . -type f -exec md5sum {} \; > backup.md5

### Exclusions

- Files with a `.md5` extension are always excluded from scanning (treated as checksum files, not data).
- Hidden directories (starting with `.`) are skipped.
- The checksum input and output files themselves are excluded.

## Design decisions

**MD5 instead of SHA-1/SHA-256:** For bit rot detection, MD5 is more than sufficient. A random bit flip has a 2⁻¹²⁸ chance of colliding — one undetected error per ~10³⁸ bits. That's roughly one undetected error per 10²⁴ 10 TB drives. The chosen-prefix collision attacks against MD5 are irrelevant here — cosmic rays don't craft adversarial inputs.

**Mtime-based classification:** No per-file timestamps stored. The checksum file's mtime is the single "last known good" timestamp. Files that changed without a newer mtime are silently corrupted. Files with a newer mtime were intentionally modified. This trades granularity for simplicity and universal tool compatibility.

**Plain text over database:** A `.md5` file is readable by humans, verifiable by `md5sum -c`, editable by any text editor, diffable by `git diff`, and doesn't require a specific tool or library version to read.

## Testing

    go test -v

Covers: argument parsing, checksum I/O, file discovery, sequential and parallel hashing, bit rot detection, modification detection, deletion detection, new file detection, `.md5` exclusion, verbose output, exit codes, edge cases (unicode filenames, deep nesting, empty directories, unreadable files).

## Credits

Developed with assistance from [Xiaomi MiMo](https://github.com/XiaomiMiMo) (MiMo-V2.5-Pro). The iterative design process — from Python prototype to Go binary, argument parsing, mtime-based classification, parallel hashing, and comprehensive test suite — was done in collaboration with MiMo. See the entire chat [here](https://aistudio.xiaomimimo.com/#/share/d419b84242d6edd049b65b31915400d2) in case you are curious.

## License

[WTFPL](http://www.wtfpl.net/) — Do What The F*** You Want To Public License.
