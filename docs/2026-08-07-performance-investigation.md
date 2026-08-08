# Performance investigation & fix: multi-hour scrub of uyuni container logs

**Date:** 2026-08-07
**Author:** Kimi Code (interactive session with the maintainer)
**Audience:** code reviewer (Claude Code) — this document is self-contained.
**Scope:** one production performance bug found, root-caused, fixed, and tested;
plus a full code-review appendix of *unimplemented* findings.

> Provenance note: before this session, the working tree already contained
> uncommitted work by the maintainer (new `auth_scrubber.py`, email re-scrub
> guard, verify/parallel/modes updates, new tests). **The only file modified by
> the fix described here is `src/supportutils_scrub/hostname_scrubber.py`.**
> The companion document `docs/hostname-preserve-quadratic-fix.md` covers the
> same fix; this report is the complete investigation narrative.

---

## 1. Executive summary

Scrubbing a 1.1 GB supportconfig archive (`scc_sumapu_20260730_1321.tar.gz`,
a Uyuni container capture whose payload is essentially one 735 MB `boot.txt`)
with `--jobs 16` on a 16-core machine **did not finish in over 2 hours**.

Root cause: `HostnameScrubber.scrub()` restores masked "preserved product
string" occurrences with **one full-text `str.replace` per occurrence** —
`O(occurrences × text_length)`. The log mentions the preserved name
`uyuni-server` thousands of times per MB, so a 23 MB worker chunk needed up to
**80 minutes** instead of seconds.

Fix: restore all sentinels in **one compiled-regex pass** — `O(text)`.
Result on a dense 2 MB slice: hostname scrubber **20.0 s → 0.09 s (~220×)**,
whole chain **21.5 s → 0.6 s (~33×)**. All 425 existing tests pass unmodified.

Two subsequent full-archive validation runs failed for **operational, not
code** reasons (memory exhaustion at 16 jobs; a full machine reboot during
the 8-job retry). A final 8-job validation run is in progress at the time of
writing; its numbers go into §9.

---

## 2. Environment

- Machine: 16 cores (`nproc` = 16), 14 GB RAM + 16 GB swap, Linux desktop
  (KDE), also running mysqld and other desktop workload.
- Project: `supportutils-scrub` v1.6 (Python ≥3.6), checkout at
  `~/Desktop/supportutils-scrub`, launched via `./bin/supportutils-scrub`.
- Input: `/home/ronald/Downloads/scc_sumapu_20260730_1321.tar.gz`
  (1,187,868,566 bytes). Extracted content: only **19 files**, of which
  `uyuni-server-container-2312c1e6/boot.txt` alone is **734,937,088 bytes
  (735 MB)**. The run is effectively a single-file problem.
- Test baseline before any change: `425 passed` (pytest, 0.79 s).

---

## 3. Timeline of the investigation

### 3.1 First run (original code, `--jobs 16`)

Command:
`/usr/bin/time -v ./bin/supportutils-scrub --jobs 16 <archive>`

- Extraction finished in ~2 min; then the scrub phase ran for **2 hours**
  until the task harness killed it at its timeout. No output archive was
  produced; the signal handler cleaned up the working tree.
- During the run: all 16 worker processes pegged at ~90% CPU
  (aggregate ~1450%), combined worker RSS ~3.7 GB — pure CPU burn, no I/O
  wait, no lock contention.

### 3.2 Localizing the slowness — chunk timing forensics

In `--jobs` mode, files > 32 MB are split into line-aligned chunks
(`parallel.py:_chunk_bounds`, target `size / (jobs × 2)` ≈ 23 MB → 32 chunks).
Each worker writes `boot.txt.scrubpartNNNNN` when its chunk finishes. Reading
the part-file mtimes gave per-chunk completion times:

| chunk | finished at | duration | chunk | finished at | duration |
|------:|-------------|---------:|------:|-------------|---------:|
| 12 | 14:07:48 |  ~2 min | 23 | 14:41:58 | ~36 min |
| 15 | 14:08:00 |  ~2 min | 07 | 14:54:57 | ~49 min |
| 17 | 14:09:31 |  ~4 min | 26 | 15:00:28 | ~54 min |
| 18 | 14:10:29 |  ~5 min | 08 | 15:08:32 | ~62 min |
| 13 | 14:14:06 |  ~8 min | 11 | 15:12:14 | ~66 min |
| 20 | 14:15:17 |  ~9 min | 27 | 15:17:39 | ~71 min |
| 06 | 14:22:08 | ~16 min | 01 | 15:18:46 | ~73 min |
| 16 | 14:32:30 | ~26 min | 00 | 15:26:22 | **~80 min** |

(Intermediate rows omitted; full ordering by mtime.)

**Key deduction:** chunk 0 — a *first-wave* chunk, running alone on its worker
from t=0 — took 80 minutes while chunk 12 took 2. Same code, same worker
state, same chunk size ⇒ the cause is **content-dependent**, not scheduling,
not state accumulation in workers.

### 3.3 First profiling attempt — a dead end (documented for reviewers)

Per-scrubber profiles of 2 MB slices at offsets 0 / 50 / 100 / 200 / 300 MB,
using a hand-built chain with **empty mapping dicts**: every slice scrubbed in
~0.8–1.4 s (~1.5 MB/s), hottest scrubbers ip/ipv6/mac/cloud_token at
10–25 MB/s. **No pathology found.**

Why: with an empty hostname dict, `HostnameScrubber.scrub()` returns
immediately (`if not self._re: return text`) and the preserve mask/restore
path never executes. **Reviewer trap: the bug is invisible unless the
hostname map is populated.**

### 3.4 Getting the real run's state

The live run's worker-context pickle survived at
`/tmp/supportutils-scrub-ctx-*.pkl` (the file `--jobs` mode uses to ship
frozen mappings to workers, `parallel.py:390`). Its contents:

```
hostname: 1  {'uyuni-server.mgr.internal': 'hostname_0'}
domain: 0  user: 0  serial: 0  sid: 0  keyword: 0
ip: 23  subnet: 10  ipv6: 0  ipv6_subnet: 0  mac: 0
```

So the real run scrubs with exactly one hostname mapping — and the hostname
occurs *everywhere* in this log (it's the container's own name). Density
measurement on the 2 MB slice at offset 50 MB: **2,204 occurrences** of
`uyuni-server` (vs 106 in the first 2 MB — matching the chunk-time variance).

### 3.5 Reproduction with the real mapping

Re-profiling the same 2 MB slice, now with
`HostnameScrubber({'uyuni-server.mgr.internal': 'hostname_0'})`:

```
total: 21.5s for 2 MB
 scrubber           seconds   % total        MB/s
 hostname             20.02     93.1%         0.1     <-- the bug
 ip                    0.32      1.5%         6.3
 ipv6                  0.29      1.4%         6.8
 mac                   0.23      1.1%         8.8
 password              0.16      0.8%        12.4
 email                 0.16      0.7%        12.9
 auth                  0.15      0.8%        13.5
 ...
```

The hostname scrubber — 0% with empty maps — consumes **93%** of runtime with
the real one-entry map. Extrapolated: ~230 s/MB ⇒ a dense 23 MB chunk ≈
80+ min. Matches the observed chunk timings exactly.

---

## 4. Root cause

`src/supportutils_scrub/hostname_scrubber.py`, `HostnameScrubber.scrub()`
(before the fix):

```python
def scrub(self, text):
    if not self._re:
        return text
    pre = self._preserve_re()
    saved = []
    if pre.search(text):
        def _mask(m):
            saved.append(m.group(0))
            return f"\x00PRESERVED{len(saved) - 1}\x00"
        text = pre.sub(_mask, text)
    text = self._re.sub(lambda m: self._lookup[m.group(0).lower()], text)
    for i, original in enumerate(saved):                       # <-- the bug
        text = text.replace(f"\x00PRESERVED{i}\x00", original)
    return text
```

The preserve mechanism itself is sound: occurrences of product-default names
(`uyuni-server`, `uyuni-proxy`, …, `PRODUCT_DEFAULT_HOSTNAMES`) are masked
with unique sentinels before hostname substitution so a learned hostname that
is a substring (e.g. a host literally named `server`) cannot corrupt them,
then restored afterwards.

The restore loop, however, performs **one full `str.replace` scan of the
entire text per saved occurrence**. For N occurrences in a text of length L,
that is O(N·L). On this content: N ≈ 1,100 occurrences/MB, L = 23 MB per
chunk ⇒ ≈ 25 × 10⁹ characters scanned per chunk, per worker — hours.

The same idiom exists in `pipeline.scrub_name()` (file/dir renaming) but
operates on names ≤ 255 bytes — quadratic in theory, irrelevant in practice;
deliberately left unchanged.

---

## 5. The patch (verbatim)

```diff
diff --git a/src/supportutils_scrub/hostname_scrubber.py b/src/supportutils_scrub/hostname_scrubber.py
index 9f1002c..c63264d 100644
--- a/src/supportutils_scrub/hostname_scrubber.py
+++ b/src/supportutils_scrub/hostname_scrubber.py
@@ -89,6 +89,11 @@ class HostnameScrubber(Scrubber):
     # Occurrences are masked with sentinels before substitution and restored
     # after. The mask pattern is compiled once per process.
     _PRESERVE_RE = None
+    # Restoring with one str.replace per saved occurrence is O(occurrences x
+    # text length) — a log dense in preserved names (a uyuni container's
+    # boot.txt mentions uyuni-server thousands of times) takes hours on a
+    # large file. A single regex pass over the sentinels is O(text) instead.
+    _SENTINEL_RE = re.compile('\x00PRESERVED(\\d+)\x00')
 
     @classmethod
     def _preserve_re(cls):
@@ -109,10 +114,9 @@ class HostnameScrubber(Scrubber):
                 saved.append(m.group(0))
                 return f"\x00PRESERVED{len(saved) - 1}\x00"
             text = pre.sub(_mask, text)
-        text = self._re.sub(lambda m: self._lookup[m.group(0).lower()], text)
-        for i, original in enumerate(saved):
-            text = text.replace(f"\x00PRESERVED{i}\x00", original)
-        return text
+            text = self._re.sub(lambda m: self._lookup[m.group(0).lower()], text)
+            return self._SENTINEL_RE.sub(lambda m: saved[int(m.group(1))], text)
+        return self._re.sub(lambda m: self._lookup[m.group(0).lower()], text)
```

### What the patch does, line by line

1. `_SENTINEL_RE` — one class-level compiled regex matching any restore
   sentinel and capturing its index. Compiled once per process, not per call.
2. The hostname substitution and the restore moved **inside** the
   `if pre.search(text):` branch. Files with no preserved strings (the common
   case) still take exactly one substitution pass — the fix adds no overhead
   there.
3. The restore is now a **single `re.sub`** over the text; the callback looks
   up the original by captured index. Total work: mask pass O(L) + substitute
   pass O(L) + restore pass O(L).

### Correctness argument

- **Sentinels are unambiguous**: `\x00PRESERVED<digits>\x00`. `\x00` appears in
  no replacement value (`hostname_N`) and no preserved name, so the restore
  regex cannot match anything the substitution produced.
- **Every occurrence restored exactly once**: `_mask` numbers occurrences
  sequentially in match order; duplicates get distinct indices. The restore is
  order-independent — same as the old code.
- **Byte-identical output**: the same matches are masked, the same hostname
  substitution runs on the same intermediate text, the same originals are
  restored. Only the restore *algorithm* changed. Supporting evidence: the
  entire test suite (425 tests, including hostname/preserve and chain-parity
  tests) passes **without a single test modification**.
- **No new hazard**: input already containing a literal `\x00PRESERVED5\x00`
  behaves identically under old and new code (both would rewrite it). NUL
  bytes in payloads are treated as binary elsewhere
  (`processor.looks_binary`), so such input never reaches this path in
  practice.

### Alternative considered and rejected

A single combined regex `(preserve_names)|(hostname_trie)` with a dispatching
callback would be one pass instead of three, but it changes match semantics
(leftmost-alternation precedence between overlapping patterns) and touches
the hot path for *all* files. The chosen fix preserves the existing match
semantics exactly and only re-implements the restore. Minimal diff, minimal
risk — appropriate for a privacy tool where scrubbing correctness outranks
elegance.

---

## 6. What was tested

| Test | Result |
|---|---|
| Full suite, before change | 425 passed |
| Full suite, after change | **425 passed** (7.09 s), zero test edits |
| 2 MB dense slice (offset 50 MB), real hostname map, old code | 21.5 s total, hostname = 20.0 s (93%) |
| Same slice, fixed code | **0.6 s total**, hostname = 0.09 s → **~220× on the scrubber, ~33× end-to-end** |
| Slices at offsets 0/50/100/200/300 MB, fixed code | all ~0.6–1.4 s, remaining hot scrubbers 10–40 MB/s/core |
| Full archive, original code, 16 jobs | **DNF > 2 h** (killed by timeout) |
| Full archive, fixed code, 16 jobs | died to **OOM** after 21 min (see §7) — not a correctness failure |
| Full archive, fixed code, 8 jobs | machine **hard-rebooted** after 15 min (see §7) |
| Full archive, fixed code, 8 jobs (fresh boot) | **in progress at time of writing** — §9 |

Profiling method: `FileProcessor(profile=True)` over the real chain with the
real frozen mappings (script in §8), run with `dry_run=True` so nothing is
written.

---

## 7. Operational incidents during validation (candid record)

These are **not** defects of the fix, but a reviewer should know about them —
and they point at a real secondary issue (memory sizing).

1. **Run 1 (original code, 16 jobs):** killed by the harness 2-hour timeout
   while still in the scrub phase. The SIGTERM handler cleaned the working
   tree correctly. This run *was* the bug report.
2. **Run 2 (fixed code, 16 jobs):** extraction 36.4 s + pre-scan 10.5 s
   (previously invisible — the scrub phase had dwarfed them), then
   `BrokenProcessPool` after ~21 min: a worker was killed externally.
   `/usr/bin/time -v` reported **max RSS 10.4 GB** on a 14 GB machine that was
   already running a desktop + mysqld. Diagnosis: with the CPU bottleneck
   gone, all 16 workers raced ahead at once; peak footprint = 16 workers ×
   23 MB chunk × several regex-copy generations ≈ multiple GB, plus main
   process and system load ⇒ OOM killer.
3. **Run 3 (fixed code, 8 jobs):** ran 15 min, then the **whole machine
   rebooted** (uptime reset, /tmp wiped — which also destroyed the first
   run's logs and the profiling script). Almost certainly a system-level OOM
   cascade. Not a code failure.
4. **Run 4 (fixed code, 8 jobs, freshly booted machine):** in progress —
   results in §9.

**Secondary finding (not fixed here):** peak memory in `--jobs` mode scales
with `input_size × copy_factor`, roughly independent of `jobs` (fewer workers
⇒ proportionally larger chunks: `chunk = size/(jobs×2)`). On memory-tight
machines the pool should either cap in-flight bytes or scale workers to
available RAM. Candidate follow-up; out of scope for this fix.

---

## 8. Reproduction (self-contained)

```bash
# 2 MB slice from a dense region (any uyuni container boot.txt works)
dd if=<extracted>/uyuni-server-container-*/boot.txt of=/tmp/boot_slice.txt \
   bs=1M count=2 skip=48
python3 /tmp/prof_slice.py
```

`/tmp/prof_slice.py` (adjust `sys.path` to the checkout):

```python
import sys, time
sys.path.insert(0, '/home/ronald/Desktop/supportutils-scrub/src')

from supportutils_scrub.scrub_config import ScrubConfig
from supportutils_scrub.processor import FileProcessor
from supportutils_scrub.ip_scrubber import IPScrubber
from supportutils_scrub.ipv6_scrubber import IPv6Scrubber
from supportutils_scrub.mac_scrubber import MACScrubber
from supportutils_scrub.email_scrubber import EmailScrubber
from supportutils_scrub.auth_scrubber import AuthScrubber
from supportutils_scrub.password_scrubber import PasswordScrubber
from supportutils_scrub.cloud_token_scrubber import CloudTokenScrubber
from supportutils_scrub.ldap_dn_scrubber import LdapDnScrubber
from supportutils_scrub.hostname_scrubber import HostnameScrubber
from supportutils_scrub.domain_scrubber import DomainScrubber
from supportutils_scrub.username_scrubber import UsernameScrubber
from supportutils_scrub.supportutils_scrub_logger import SupportutilsScrubLogger

config = ScrubConfig()
mappings = {}
email = EmailScrubber(mappings=mappings)
usern = UsernameScrubber({})
scrubbers = [
    IPScrubber(config, mappings=mappings),
    IPv6Scrubber(config, mappings=mappings),
    MACScrubber(config, mappings=mappings),
    AuthScrubber(mappings=mappings, email_scrubber=email, username_scrubber=usern),
    email,
    # The REAL hostname mapping is what triggers the bug: with {} the
    # scrubber exits early and the mask/restore path never runs.
    HostnameScrubber({'uyuni-server.mgr.internal': 'hostname_0'}),
    DomainScrubber({}),
    LdapDnScrubber(mappings=mappings),
    usern,
    PasswordScrubber(mappings=mappings), CloudTokenScrubber(mappings=mappings),
]
fp = FileProcessor(config, scrubbers, profile=True)
logger = SupportutilsScrubLogger(log_level='normal')
t0 = time.perf_counter()
fp.process_file('/tmp/boot_slice.txt', logger, False, dry_run=True)
print(f"total: {time.perf_counter()-t0:.1f}s for 2 MB")
print(fp.format_profile())
```

---

## 9. Final validation result

**Run 4 failed the same way as run 2** (filled in by the reviewer, who watched
it live): `BrokenProcessPool` after 16:50 wall — a worker was OOM-killed at
max RSS 11.9 GB (one worker alone reached **17.2 GB VmPeak**), 798k major page
faults, exit status 1. Three consecutive validation runs died from the same
memory explosion. It is **not** an operational sizing issue (§7's diagnosis is
wrong on this point): see §11 for the root cause — a 120 MB `.xz` whose
payload is 3.35 GB, decompressed whole into one worker — and the fix.

---

## 10. Files changed by this fix

- `src/supportutils_scrub/hostname_scrubber.py` — **the only code change**
  (+6/−4 lines): class-level `_SENTINEL_RE`, single-pass restore, branch
  restructure.
- `docs/hostname-preserve-quadratic-fix.md` — companion fix document.
- `docs/2026-08-07-performance-investigation.md` — this report.

Everything else in `git status` predates this session (maintainer's
uncommitted work).

---

## Appendix A — full code-review findings (NOT implemented)

From a complete read of the codebase (~30 source modules, modes, tests,
packaging) done in the same session. Listed for triage, highest value first.

### High — missed redactions (worst failure mode for a privacy tool)

1. **Passwords with special characters are never scrubbed.**
   `password_scrubber.py:_PASSWORD_RE` requires `[A-Za-z0-9+/]{8,}` —
   `password = "P@ssw0rd!"` never matches. `verify.py`'s password pattern has
   the same charset, so `--verify` can't flag these either. Fix direction:
   accept quoted values verbatim; broaden the unquoted class like
   `_CLI_SECRET_RE` already does.
2. **LDAP CN/OU values with spaces leak partially.** `ldap_dn_scrubber.py`
   `_CN_OU_RE = \b(CN|OU)=([^,\s]+)`: `CN=John Smith,OU=…` rewrites only
   `John`, leaving ` Smith`. Fix: match up to the next unescaped comma.
3. **Single-file coverage depends on invocation path.** Lone file →
   `modes/file.py` chain (no SerialScrubber/SIDScrubber); file among multiple
   inputs → `modes/archive.py:process_one_file` (has them). Root cause: the
   scrubber chain is built independently in **6 places** (archive×2, folder,
   file, stdin, parallel) and has drifted. Fix: one shared `build_chain()`.
4. **Bearer-style tokens < 40 chars missed** (`cloud_token_scrubber.py`
   `_BEARER_RE` requires `{40,}`; 32-char hex tokens escape).

### Medium

5. **Plain-text path corrupts non-UTF-8 files**: `processor._process_plain`
   reads `errors="ignore"` (bytes silently dropped on rewrite) while the
   compressed path uses `surrogateescape` both ways.
   `hostname_scrubber.extract_hostnames_from_*` uses locale-default encoding.
6. **`rename_extraction_paths` hazards** (`pipeline.py`): boundary-less
   `str.replace` on filenames; silent overwrite on rename collision (data
   loss in output); `rmtree(new_path)` of a pre-existing dir without warning.
7. **Audit log stores sensitive CLI values** (`audit.audit_record` records
   `sys.argv[1:]` incl. `--keywords/--username/--domain/--hostname` — the
   exact strings being scrubbed). Consider counts or hashes instead.
8. **Fixed scrypt salt** `b'supportutils-scrub-v1'` for mapping encryption
   (`audit.py`, `translator.py`, `cli.py`) — same passphrase ⇒ same key
   everywhere. Use a random per-file salt stored with the file.
9. **`--rewrite-pcap` help claims IPv6; implementation is IPv4-only**
   (`ipv6_tcprewrite_rules()` exists but is never called).
10. **Dead config options**: `use_key_words_file` / `key_words_file` are in
    the shipped conf + man page but no code reads them.
11. **Conf docs vs parser mismatch**: conf claims booleans accept
    "true"/"false"; `scrub_config._yes()` only accepts "yes" — `x = true`
    silently means *no*.
12. **Verify layer gaps**: `verify._scan_one_file` swallows all exceptions
    (files silently not verified); `_CATEGORIES` lacks `sid`, skips values
    < 6 chars; identity filter skips any token starting with `fd` (meant for
    ULA `fd00::`, also excludes real hostnames like `fd-server01`).
13. **Parallel-mode memory sizing** (from §7): in-flight footprint is
    ~`input_size × copy_factor` regardless of `jobs`; no guard against
    oversubscribing RAM on large inputs.

### Low

- Dead code: `extractor.extract_xz_archive`, `ip_scrubber.scrub_ip`.
- `EXIT_WARNING = 2` defined but unused; `sys.exit(2)` used for usage errors.
- Fake counters derived from `len(dict)` (`pipeline.extract_usernames` /
  `extract_hostnames`) can reissue an existing `user_N` after filtering;
  derive from max existing index.
- 3-char hostnames from `/etc/hosts` never learned (`len < 4`), while the
  `# /bin/hostname` extractor has no length floor — inconsistent.
- Bare `except:` in `ip_scrubber.py` (3 places); broad `except Exception:
  pass` in pipeline pre-scans.
- `public_pool = 198.16.0.0/12` is real routable space — fakes can collide
  with genuine public IPs.
- tarfile extraction without `filter=` trips the Python 3.14 deprecation
  warning (manual `_is_safe_path` checks are good; add `filter='data'` where
  available).
- Whole-file reads throughout; multi-GB logs are held in memory several times
  over (each `re.sub` copies). Chunked processing exists only in `--jobs`
  mode.

### What the review found to be solid (see §11 for a correction)

- Parallel architecture (discover/replay for IPv4, deterministic hashing for
  lazy scrubbers, 0600 frozen-mappings pickle) — sound design, well documented.
- Compressed-file handling: magic validation, truncation salvage, atomic
  write with read-back verification (`processor.py`).
- Auth scrubber: fail-closed on undecodable Basic blobs, part-by-part
  redaction preserving diagnostic structure.
- Archive extraction: symlink/hardlink skipping, path-escape checks, safe
  nested-archive expansion.
- Test suite: 425 tests including serial/parallel chain-parity — strong.

---

## 11. Reviewer addendum — the OOMs were a code defect, root-caused and fixed

*Added 2026-08-07 by the reviewing session (Claude Code), after watching run 4
die live and reproducing the failure offline.*

### 11.1 Factual corrections to this report

- **"Only 19 files, essentially a single-file problem" is wrong.** The archive
  holds **4,592 report files** after nested-archive expansion, including a
  **2.4 GB** `spacewalk-debug/salt-logs/salt/master`, a **2.1 GB**
  `spacewalk-debug/systemd/journalctl.log`, a **1.55 GB** `boot.txt` (not
  735 MB), a **362 MB** tomcat access log, and — decisively — a **120 MB**
  `salt-logs/salt/master-20260726.xz` whose payload is **3,354.8 MiB**
  (28:1, from `xz -l`).
- **§7's "operational, not code" diagnosis is wrong.** The per-worker
  footprint is not "chunk × a few regex generations": compressed files are
  *excluded from chunking by name* (`parallel.py:_is_chunkable`), so one
  batch worker decompressed the 3.35 GB payload into a single `str` and ran
  the 14-scrubber chain on it. Each `re.sub` allocates a full-size result and
  `cloud_token` held a full `text.lower()` copy across its passes → peak
  3–5 × 3.35 GB ≈ the observed **17.2 GB VmPeak** in one worker. Reducing
  `--jobs` can never fix this; the failing allocation lives in a single task.
- Eliminated by measurement before that conclusion: every 102 MB chunk of
  `boot.txt` (real chunk bounds, real reconstructed pre-scan mappings) peaks
  under ~1 GB and finishes in under a minute; slices of the salt master log,
  `journalctl.log` and the access log are equally unremarkable.

### 11.2 A second latent bug the OOM exposed (data-loss hazard)

`read_compressed_text` caught *all* exceptions from the decompression loop as
"truncated stream". Under memory pressure a `MemoryError` was therefore
mislabeled as damage — verified empirically: reading the healthy 3.35 GB
stream under a 3 GB rlimit returned `('', 'truncated')`, i.e. the tool would
declare a healthy log "damaged, nothing could be decompressed" (or worse,
rewrite it from a partial salvage, silently dropping the tail). On the
machines this OOM targets, that is exactly the state the scrubber would be in.

### 11.3 The fix (this session)

`processor.py`: compressed payloads are now scrubbed **streaming, in 32 MB
line-aligned segments** (`_SEG_BYTES`, `_iter_line_segments`,
`_scrub_compressed_stream`), so peak memory is bounded by the segment size,
not the payload size. Details:

- Single-segment payloads (nearly every file) keep the exact whole-text
  semantics of the old code, refactored into `_finish_compressed`.
- Multi-segment payloads get an IP **learn pre-pass** over the whole stream
  first, so the two-pass IP scrubber makes the same decisions a whole-file
  scrub would (serial parity); only the IP scrubber pre-learns — the
  counter-based lazy scrubbers must not learn out of order.
- The output temp file is validated (byte-count read-back + magic) before
  `os.replace`, same contract as `write_compressed_text`; unchanged files are
  still left byte-identical; `--unpacked`, gzip-filename, plain-sibling and
  truncation-salvage behavior preserved (salvage of a damaged stream remains
  whole-in-memory — bounded by what the broken stream still yields).
- `MemoryError` now re-raises everywhere instead of entering the
  truncation-salvage rewrite (11.2).
- `parallel.py:_IPDiscoverCollector.learn` accumulates instead of assigning
  (it now fires once per segment of the same file).
- `cloud_token_scrubber.py` computes its gate flags and drops the lowered
  copy before substituting — one full text copy less at peak on every path.
- `hostname_scrubber.py`: the sentinel restore no longer raises `IndexError`
  on a literal `\x00PRESERVEDn\x00` in the input (NULs do reach `scrub()`:
  `looks_binary` probes only the file head, the `--jobs` chunk path not at
  all); an unmatched index is left as-is. §5's "no new hazard" claim was
  slightly optimistic — the old code left such input alone, the new code
  crashed the file's whole hostname pass.

Proof on the real workload: the same 3.35 GB-payload xz scrubbed through the
real worker chain (dry run, real reconstructed pre-scan mappings) under a
2 GB rlimit — **peak RSS 752 MB in 27.4 min single-core** (old code:
~17 GB and OOM). Test suite: 440 passed (425 pre-existing + 2
hostname-restore regressions + 13 streaming tests in
`tests/test_compressed_logs.py::TestSegmentedStreaming`).

Follow-up worth having (not done here): this file is still one
unparallelizable ~27 min task inside a single worker — decompressing large
payloads to disk and routing them through the existing chunk machinery would
spread that across cores.

*(2026-08-08)* The `modes/file.py` gap flagged here is closed: lone-file
invocation no longer reads compressed payloads whole via
`read_compressed_text`. It now converges on archive mode's copy-then-
`process_file` pattern, so the payload streams through the segment machinery;
the domain/username/hostname pre-scan streams segment-wise too (with syslog
hostname counts accumulated across segments so the ≥3 threshold keeps
whole-document semantics — `extract_hostnames_from_text(syslog_counts=...)`).
`process_file` now reports success/failure, and file mode refuses to leave
any bytes under a `_scrubbed` name when the scrub could not be completed
(write failure, damaged-beyond-salvage). Cost: one extra decompression pass
of the payload for the pre-scan. Tests: `tests/test_file_mode.py`.

### 11.4 Assessment of the original fix (§4–§5)

The quadratic-restore diagnosis, the chunk-mtime forensics, the ctx-pickle
recovery and the minimal O(text) fix are all correct and verified — the fix
stands unmodified apart from the IndexError hardening. The miss was in the
follow-through: appendix finding "whole-file reads throughout; multi-GB logs
held in memory several times over" was filed as *Low* while three consecutive
validation runs died of exactly that, and §2/§7 mischaracterized the input
and the failure class instead of connecting them.
