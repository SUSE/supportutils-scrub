# Output naming convention

This is a stable contract. The expected names below are frozen by
`tests/test_naming.py`; changing any of them is a breaking change for users
and scripts that consume scrubbed output, and needs a very good reason.

All `_scrubbed` names are produced by two functions in `processor.py` —
`scrubbed_output_name()` for files and `append_scrubbed()` for folder and
archive base names. No other code may build a `_scrubbed` name by hand.

## Master rule

The `_scrubbed` marker appears **exactly once**, on the outermost artifact
passed to the tool:

- **Files:** marker goes immediately before the file extension; a compression
  extension (`.gz`, `.xz`, `.bz2`) stays outermost.
- **Folders and archives:** marker is appended to the base name.
- Hostnames and domains appearing in any output name are obfuscated.
- A name already carrying the marker is never marked again (idempotent);
  re-running overwrites the previous output.
- Extension matching is case-insensitive; original casing is preserved.

## Supportconfig archives (`.txz`, `.tar.xz`, `.tgz`, `.tar.gz`, `.tbz`, `.tbz2`, `.tar.bz2`)

Archive extension stripped (double extensions handled), hostname in the name
obfuscated, `_scrubbed.txz` appended. Output is always repacked as `.txz`
regardless of input compression.

| Input | Output |
|---|---|
| `scc_myhost_250101_1200.txz` | `scc_host001_250101_1200_scrubbed.txz` |
| `scc_myhost_250101_1200.tar.gz` | `scc_host001_250101_1200_scrubbed.txz` |

The extraction working folder follows the folder rule:
`scc_host001_250101_1200_scrubbed/`.

## Files inside an archive or folder

Names are kept unchanged — no `_scrubbed` suffix; the container carries the
marker. Exceptions:

| Scenario | Result |
|---|---|
| name/dir contains a hostname (`myhost_boot.log`, `logs/myhost/`) | renamed with the fake hostname |
| `sar20250101.xz` (text sar) | name kept, decompressed → scrubbed → recompressed |
| `sa20250101[.xz]` (binary) | deleted from output |
| nested archive (incl. plain `.tar`) | replaced by a folder named after it (ext stripped, `_1`, `_2` on collision), contents scrubbed, tar removed, stays unpacked |

## Loose folder

Copy created next to the original (original untouched); hostname in the
folder name obfuscated. A folder already named `*_scrubbed` is re-scrubbed
in place.

| Input | Output |
|---|---|
| `mylogs/` | `mylogs_scrubbed/` |
| `myhost_logs/` | `host001_logs_scrubbed/` |

## Single files (plain or compressed)

| Input | Output |
|---|---|
| `messages.log` | `messages_scrubbed.log` |
| `messages` | `messages_scrubbed` |
| `app.error.log` | `app.error_scrubbed.log` |
| `.env` | `.env_scrubbed` |
| `myhost.log` | `host001_scrubbed.log` |
| `MESSAGES.LOG` | `MESSAGES_scrubbed.LOG` |
| `messages.log.xz` | `messages_scrubbed.log.xz` |
| `boot.log.bz2` | `boot_scrubbed.log.bz2` |
| `traces.gz` | `traces_scrubbed.gz` |
| `messages_scrubbed.log` (re-run) | `messages_scrubbed.log` |

## PCAP (`--rewrite-pcap`)

| Input | Output |
|---|---|
| `capture.pcap` | `capture_scrubbed.pcap` |
| `capture` | `capture_scrubbed.pcap` |

## `--unpacked` (opt-in variant)

The default behavior above preserves compression and repacks archives.
With `--unpacked` the output stays fully unpacked instead; the naming rules
are otherwise identical:

| Input | Output with `--unpacked` |
|---|---|
| `scc_myhost_250101.txz` | `scc_host001_250101_scrubbed/` folder — no `.txz` is created |
| inner `messages-20250101.xz` / `.gz` / `.bz2` | `messages-20250101` — written plain, compression extension dropped |
| inner `sar20250101.xz` | `sar20250101` |
| single file `messages.log.xz` | `messages_scrubbed.log` — plain |

Nested tars are always unpacked, with or without the flag.

## stdin

Output goes to stdout; no file is created.

## Tool artifacts (separate namespace, never `_scrubbed`)

`obfuscation[_<fakehost>]_<timestamp>_{mappings,audit,report}.json`
