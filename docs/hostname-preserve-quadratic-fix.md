# Fix: quadratic sentinel-restore in HostnameScrubber (multi-hour scrub of dense logs)

Date: 2026-08-07
Author: analysis + fix by Kimi Code, during a live performance investigation
Status: implemented, all 425 tests pass; full-archive validation run in flight

This document describes one concrete fix (in `src/supportutils_scrub/hostname_scrubber.py`)
with full context — symptom, evidence, root cause, the change, correctness argument,
and measurements — plus an appendix of further findings from a full code review that
are **not** implemented and are candidates for follow-up work.

Note on provenance: the working tree contained pre-existing uncommitted changes
(auth scrubber, email re-scrub guard, verify/parallel/mode updates) before this
fix was made. The only file changed by THIS fix is `hostname_scrubber.py`.

---

## 1. Symptom

Scrubbing `scc_sumapu_20260730_1321.tar.gz` (1.1 GB, a Uyuni container capture whose
payload is essentially one 735 MB `boot.txt`) with `--jobs 16` on a 16-core machine:

- Extraction: ~2 min. Pre-scan: ~1 min. Then the scrub phase ran **over 2 hours
  without finishing** (the run was killed by a timeout).
- The big file was split into 32 line-aligned chunks of ~23 MB (`parallel.py`,
  `_chunk_bounds`). Observed per-chunk wall times from part-file mtimes grew
  monotonically with content position: ~2 min for early chunks, up to **80 min for
  chunk 0** and 60–80 min for several other chunks — all for identical 23 MB inputs.
- All 16 workers stayed at ~90% CPU the whole time (pure compute, not I/O or lock
  contention). Aggregate throughput: ~0.2 MB/s.

The chunk-time variance (2 min vs 80 min for same-size chunks on identical-code
workers) proved the cause was **content-dependent**, not scheduling or I/O.

## 2. Root cause

`HostnameScrubber.scrub()` protects preserved product strings (`uyuni-server`,
`uyuni-proxy`, …) from substring corruption by masking each occurrence with a
sentinel, running the hostname substitution, then restoring the originals.

The old restore did **one full-text `str.replace` per saved occurrence**:

```python
for i, original in enumerate(saved):
    text = text.replace(f"\x00PRESERVED{i}\x00", original)
```

Cost model: `O(occurrences × text_length)`.

A Uyuni container's `boot.txt` mentions `uyuni-server` extremely often (salt-master
event streams, podman logs, systemd unit names). Measured density: **2,204
occurrences in a single 2 MB slice** (offset 50 MB). For a 23 MB chunk with tens of
thousands of occurrences, the restore pass alone scans terabytes of string data —
hours per chunk. This exactly explains the content-dependent chunk times: chunks are
slow precisely where `uyuni-server` mentions are dense.

Why profiling initially missed it: with an **empty** hostname dict, `scrub()` returns
early (`if not self._re: return text`) and the mask/restore path never runs. Only
profiling with the real frozen mapping (`{'uyuni-server.mgr.internal': 'hostname_0'}`
— taken from the live run's ctx pickle `/tmp/supportutils-scrub-ctx-*.pkl`)
reproduced it:

| slice (2 MB, offset 50 MB) | hostname scrubber | total |
|---|---|---|
| empty hostname dict        | ~0 s (early exit) | 1.3 s |
| real hostname dict, old code | **20.0 s (93% of total)** | 21.5 s |
| real hostname dict, fixed  | 0.09 s | **0.6 s** |

## 3. The fix

Restore all sentinels in **one regex pass** instead of N string replacements.
The sentinel format is unchanged, so the mask pass and everything downstream are
untouched.

```diff
@@ class HostnameScrubber:
     _PRESERVE_RE = None
+    # Restoring with one str.replace per saved occurrence is O(occurrences x
+    # text length) — a log dense in preserved names (a uyuni container's
+    # boot.txt mentions uyuni-server thousands of times) takes hours on a
+    # large file. A single regex pass over the sentinels is O(text) instead.
+    _SENTINEL_RE = re.compile('\x00PRESERVED(\\d+)\x00')
 
@@ def scrub(self, text):
         if pre.search(text):
             def _mask(m):
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

Two structural notes:

- The hostname substitution and restore moved **inside** the `if pre.search(text):`
  branch, so the common case (no preserved string present) keeps doing exactly one
  substitution pass — no extra regex pass added for files without preserved names.
- `_SENTINEL_RE` is compiled once at class definition, not per call.

### Correctness argument

- Sentinels are `\x00PRESERVED<decimal>\x00` — unambiguous, and `\x00` cannot appear
  in any replacement value (`hostname_N`), so the restore regex can never match
  something the substitution produced.
- Mask numbering is sequential from 0 in match order; the restore looks up
  `saved[int(m.group(1))]` — every masked occurrence is restored exactly once,
  regardless of order or duplication (the old code handled duplicates correctly too,
  since each occurrence got its own index).
- A pathological input already containing a literal `\x00PRESERVED5\x00` behaves the
  same under old and new code (both would rewrite it); NUL bytes in text files are
  already treated as binary elsewhere (`processor.looks_binary`), so this is a
  non-regression, not a new hazard.
- Behavior is byte-identical to the old code: the same matches are masked, the same
  substitutions applied, the same strings restored. Only the restore algorithm
  changed. The full test suite (425 tests, including hostname/preserve and
  chain-parity tests) passes unchanged — no test edits were needed, which is itself
  evidence of behavioral equivalence.

### Why not a combined single regex `(preserve)|(hostnames)`?

A single-pass alternation would also be O(text), but it changes match semantics
(leftmost-alternation precedence between overlapping preserve/hostname patterns)
and touches the hot path for all files. The chosen fix keeps the existing match
semantics exactly and only re-implements the restore. Minimal diff, minimal risk.

## 4. What was deliberately NOT changed

- `pipeline.scrub_name()` uses the same mask/restore idiom, but only on file and
  directory **names** (≤255 bytes). Quadratic in theory, irrelevant in practice;
  left untouched to keep the diff minimal.
- No other scrubber has a per-occurrence full-text loop; the profile shows the
  remaining hot scrubbers (ip, mac, ipv6, password, auth, email) all run at
  10–40 MB/s per core on this content — acceptable.

## 5. Verification

- `python3 -m pytest -q` → **425 passed** (same count as before the change).
- Micro-benchmark: the same 2 MB dense slice goes from 21.5 s to 0.6 s total
  (hostname scrubber 20.0 s → 0.09 s, ~220×; overall ~33× on this content).
- Full-archive validation attempts (candid record):
  1. `--jobs 16 --verify`: scrub compute was dramatically faster (extraction
     36 s + pre-scan 10.5 s, then straight into the apply phase), but the run
     **died to memory pressure, not CPU**: a pool worker was killed
     (`BrokenProcessPool`), `/usr/bin/time -v` reported max RSS 10.4 GB on a
     14 GB machine. With the hostname bottleneck gone, all 16 workers raced
     ahead simultaneously and the combined footprint (each worker holds a 23 MB
     chunk plus several regex-copy generations) exceeded RAM.
  2. `--jobs 8 --verify`: ran 15 min, then the **machine hard-rebooted**
     (uptime reset, /tmp wiped) — almost certainly a full-system OOM. Not a
     code failure.
  3. Final attempt and its numbers: see "Validation result" below.

  Operational note: on memory-constrained machines, use fewer `--jobs` for
  very large inputs — the per-worker footprint scales with chunk size
  (`file_size / (jobs × 2)`, min 8 MB). A possible code improvement (not done
  here): scale `--jobs` to available memory, or cap chunk count.

## 5b. Validation result

Run 4 (jobs 8, fresh boot) failed like run 2: `BrokenProcessPool` after
16:50, one worker OOM-killed (17.2 GB VmPeak, max run RSS 11.9 GB). The
hostname fix itself is validated (§5's micro-benchmarks, 425 tests); the
repeated OOMs turned out to be a separate code defect, not an operational
sizing issue: compressed files bypass `--jobs` chunking, and a 120 MB
`salt/master-20260726.xz` in this capture holds a 3.35 GB payload (28:1)
that one worker decompressed and scrubbed as a single string. Root cause,
fix (streaming line-aligned segments in `_process_compressed`), and full
corrections to this document's §1/§5 premises ("19 files / single-file
problem" — the archive holds 4,592 files) are in
`docs/2026-08-07-performance-investigation.md` §9 and §11.

## 6. Reproduction recipe (for reviewers)

```bash
# 2 MB slice from a dense region of the log (any large uyuni container log works)
dd if=<extracted>/uyuni-server-container-*/boot.txt of=/tmp/boot_slice.txt bs=1M count=2 skip=48

python3 /tmp/prof_slice.py
```

`/tmp/prof_slice.py` (self-contained; adjust `sys.path` to the checkout):

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
    # The REAL hostname mapping is what triggers the bug: with {} the scrubber
    # exits early and the preserve mask/restore path never runs.
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

Key reviewer trap: profiling with an empty hostname dict exits early and shows
nothing — the bug only fires when the preserve mask runs.

---

## Appendix A — other findings from the full code review (NOT implemented)

These came out of a complete read of the codebase (all src modules, modes, tests,
packaging). Listed for triage; none of these are addressed by the fix above.

### High — missed redactions

1. **Passwords with special characters are never scrubbed.**
   `password_scrubber.py` `_PASSWORD_RE` requires `[A-Za-z0-9+/]{8,}` —
   `password = "P@ssw0rd!"` never matches (charset stops at `@`, remaining alnum
   run < 8). `verify.py`'s password pattern has the same charset, so `--verify`
   won't flag these either. Suggested: accept quoted values verbatim and broaden
   the unquoted class like `_CLI_SECRET_RE` already does.
2. **LDAP CN/OU values with spaces leak partially.** `ldap_dn_scrubber.py`
   `_CN_OU_RE` uses `([^,\s]+)`: `CN=John Smith,OU=...` only rewrites `John`,
   leaving ` Smith`. Common in AD DNs. Suggested: match up to the next unescaped
   comma.
3. **Single-file mode coverage depends on invocation path.** A lone file goes
   through `modes/file.py` (no SerialScrubber/SIDScrubber in the chain); a file
   among multiple inputs goes through `modes/archive.py:process_one_file` (has
   them). Root cause: the scrubber chain is constructed independently in 6 places
   and has already drifted. Suggested: one shared `build_chain()` used by all
   modes (archive, folder, file, stdin, parallel workers).
4. **Bearer-style tokens < 40 chars missed.** `cloud_token_scrubber.py`
   `_BEARER_RE` requires `{40,}`; 32-char hex tokens escape.

### Medium

5. **Plain-text path corrupts non-UTF-8 files.** `processor._process_plain` reads
   with `errors="ignore"` (bytes dropped on rewrite) while the compressed path
   uses `surrogateescape` both ways. Make plain consistent.
   `hostname_scrubber.extract_hostnames_from_*` opens with locale default encoding.
6. **`rename_extraction_paths` hazards** (`pipeline.py`): boundary-less
   `str.replace` on filenames (host `web` mangles `webserver.log`), silent
   overwrite on rename collision (data loss in output), and `rmtree(new_path)`
   of a pre-existing directory without warning.
7. **Audit log stores sensitive CLI values.** `audit.audit_record` records
   `sys.argv[1:]`, including `--keywords/--username/--domain/--hostname` — the
   exact strings being scrubbed (file is 0600, but still). Consider counts/hashes.
8. **Fixed scrypt salt** (`b'supportutils-scrub-v1'`) for mapping encryption in
   `audit.py`, `translator.py`, `cli.py` — same passphrase → same key everywhere.
   Use a random per-file salt prepended to the payload.
9. **`--rewrite-pcap` help claims IPv6; implementation is IPv4-only.**
   `ipv6_scrubber.ipv6_tcprewrite_rules()` exists but is never called.
10. **Dead config options.** `use_key_words_file` / `key_words_file` are in the
    shipped conf and the man page but no code reads them.
11. **Conf docs vs parser mismatch.** Conf claims booleans accept "true"/"false";
    `scrub_config._yes()` only accepts "yes" — `x = true` silently means no.
12. **Verify layer gaps.** `verify._scan_one_file` swallows all exceptions (files
    silently not verified); `_CATEGORIES` lacks `sid` and skips values < 6 chars;
    identity filter skips any token starting with `fd` (meant for ULA `fd00::`).

### Low

- Dead code: `extractor.extract_xz_archive`, `ip_scrubber.scrub_ip`.
- `EXIT_WARNING = 2` defined but unused; `sys.exit(2)` used for usage errors.
- Fake-counter derivation from `len(dict)` (`pipeline.extract_usernames` /
  `extract_hostnames`) can reissue an existing `user_N` after filtering; derive
  from max index instead.
- 3-char hostnames from `/etc/hosts` never learned (`len < 4` check), while the
  `# /bin/hostname` extractor has no floor — inconsistent.
- Bare `except:` in `ip_scrubber.py` (3 places); broad `except Exception: pass`
  in pipeline pre-scans.
- `public_pool = 198.16.0.0/12` is real routable space — fakes can collide with
  genuine public IPs.
- tarfile extraction without `filter=` triggers the Python 3.14 deprecation
  warning (manual `_is_safe_path` checks are good; add `filter='data'` where
  available).
- Whole-file reads throughout; a multi-GB log is held in memory several times
  over (each `re.sub` copies). Chunked processing exists only in `--jobs` mode.
