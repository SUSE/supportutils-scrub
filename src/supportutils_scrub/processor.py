# processor.py

import os
import bz2
import gzip
import lzma
import re
import time
from supportutils_scrub.keyword_scrubber import KeywordScrubber
from supportutils_scrub.supportutils_scrub_logger import SupportutilsScrubLogger


BINARY_SA_PATTERN = re.compile(r"^sa\d{8}(\.xz)?$")
BINARY_OBJ_PATTERN = re.compile(r"^.*\.obj$", re.IGNORECASE)
SAR_XZ_PATTERN = re.compile(r'^sar\d{8}\.xz$')
SAR_PLAIN_PATTERN = re.compile(r'^sar\d{8}$')

# Single-file compressed logs (traces.gz, logging.xz, boot.log.bz2, ...).
# Tar archives are excluded: their payload is a tar stream, not text.
_TAR_SUFFIXES = ('.tar.gz', '.tgz', '.tar.xz', '.txz', '.tar.bz2', '.tbz', '.tbz2')
_COMPRESS_OPENERS = {'.gz': gzip.open, '.xz': lzma.open, '.bz2': bz2.open}


def compressed_opener(base_name):
    """Return (ext, open_func) for single-file compressed names, else None."""
    low = base_name.lower()
    if low.endswith(_TAR_SUFFIXES):
        return None
    for ext, opener in _COMPRESS_OPENERS.items():
        if low.endswith(ext):
            return ext, opener
    return None


def strip_compression_ext(name):
    """Drop a single-file compression extension (.gz/.xz/.bz2) if present."""
    comp = compressed_opener(os.path.basename(name))
    return name[:-len(comp[0])] if comp else name


def append_scrubbed(name):
    """Add the '_scrubbed' marker unless the name already carries it.

    Used for folder and archive base names; keeps re-runs on scrubbed
    output from doubling the marker."""
    return name if name.lower().endswith('_scrubbed') else name + '_scrubbed'


def scrubbed_output_name(path):
    """Canonical name for a scrubbed single-file output (see
    docs/naming-convention.md). '_scrubbed' goes before the file extension,
    a compression extension (.gz/.xz/.bz2) stays outermost, and a name that
    already carries the marker is returned unchanged.

        messages.log          -> messages_scrubbed.log
        messages.log.xz       -> messages_scrubbed.log.xz
        traces.gz             -> traces_scrubbed.gz
        messages              -> messages_scrubbed
        messages_scrubbed.log -> messages_scrubbed.log

    Directories and tar archives are named via append_scrubbed(); this
    covers every single-file output path."""
    comp = compressed_opener(os.path.basename(path))
    comp_ext = path[-len(comp[0]):] if comp else ''
    stem = path[:-len(comp_ext)] if comp_ext else path
    root, ext = os.path.splitext(stem)
    return append_scrubbed(root) + ext + comp_ext

_SCRUB_INFO_HEADER = (
    "#" + "-" * 93 + "\n"
    "# INFO: This file was processed by supportutils-scrub to remove sensitive data. Review before sharing.\n"
    "#" + "-" * 93 + "\n\n"
)

_CONFIG_GATES = {
    'ip':       lambda cfg: cfg.obfuscate_public_ip or cfg.obfuscate_private_ip,
    'ipv6':     lambda cfg: cfg.obfuscate_ipv6,
    'mac':      lambda cfg: cfg.obfuscate_mac,
    'hostname': lambda cfg: cfg.obfuscate_hostname,
    'domain':   lambda cfg: cfg.obfuscate_domain,
    'user':     lambda cfg: cfg.obfuscate_username,
}


class FileProcessor:
    def __init__(self, config, scrubbers, profile=False, learn_only=False, decompress=False):
        self.config = config
        self.scrubbers = list(scrubbers)
        self._by_name = {s.name: s for s in self.scrubbers}

        # decompress (--unpacked): write compressed files (.gz/.xz/.bz2) back
        # plain, dropping the compression extension, instead of recompressing.
        self.decompress = decompress

        # learn_only: call each scrubber's learn() (discover/allocate without
        # rebuilding the text) instead of scrub(). For the parallel pre-pass,
        # which only needs the mappings. Intended for a single scrubber.
        self.learn_only = learn_only
        self.profile = profile
        # name -> {'time': seconds, 'bytes': total input bytes, 'calls': n}
        self.prof = {}
        # (basename, seconds, bytes) per file, slowest-first when reported
        self.file_prof = []

        for s in self.scrubbers:
            if isinstance(s, KeywordScrubber) and not s.is_loaded():
                s.load_keywords()

    def __getitem__(self, name):
        return self._by_name.get(name)

    def merge_profile(self, other_prof, other_file_prof=None):
        """Fold another FileProcessor's profile data (e.g. from a worker)."""
        for name, rec in other_prof.items():
            dst = self.prof.setdefault(name, {'time': 0.0, 'bytes': 0, 'calls': 0})
            dst['time'] += rec['time']
            dst['bytes'] += rec['bytes']
            dst['calls'] += rec['calls']
        if other_file_prof:
            self.file_prof.extend(other_file_prof)

    def format_profile(self, top_files=15):
        """Return a human-readable timing breakdown."""
        if not self.prof:
            return "No profile data collected."
        total = sum(r['time'] for r in self.prof.values()) or 1e-9
        lines = []
        lines.append("\n" + "=" * 64)
        lines.append(" Scrub profile — time per scrubber")
        lines.append("=" * 64)
        lines.append(f" {'scrubber':<14}{'seconds':>12}{'% total':>10}{'MB/s':>12}")
        lines.append("-" * 64)
        for name, r in sorted(self.prof.items(), key=lambda kv: kv[1]['time'], reverse=True):
            mbps = (r['bytes'] / (1024 * 1024)) / r['time'] if r['time'] > 0 else 0
            lines.append(f" {name:<14}{r['time']:>12.2f}{100*r['time']/total:>9.1f}%{mbps:>12.1f}")
        lines.append("-" * 64)
        lines.append(f" {'TOTAL':<14}{total:>12.2f}{100.0:>9.1f}%")
        if self.file_prof:
            lines.append("\n Slowest files:")
            for base, secs, nbytes in sorted(self.file_prof, key=lambda x: x[1], reverse=True)[:top_files]:
                lines.append(f"   {secs:>8.2f}s  {nbytes/(1024*1024):>8.1f} MB  {base}")
        lines.append("=" * 64 + "\n")
        return "\n".join(lines)

    def process_file(self, file_path, logger: SupportutilsScrubLogger, verbose_flag, dry_run=False):
        # dry_run: run scrubbers to populate mappings but never write or delete
        # files. Used by the parallel pre-pass to build IP/IPv6/MAC maps with
        # the exact same file handling as the real run.
        base_name = os.path.basename(file_path)

        if BINARY_SA_PATTERN.match(base_name) or BINARY_OBJ_PATTERN.match(base_name):
            if dry_run:
                return
            print(f"        {base_name} [binary] (removed)")
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"[!] Failed to remove binary file {file_path}: {e} ")
            return

        is_sar_xz_file   = bool(SAR_XZ_PATTERN.match(base_name))
        is_sar_plain_file = bool(SAR_PLAIN_PATTERN.match(base_name))

        try:
            if is_sar_xz_file:
                with lzma.open(file_path, mode="rt", encoding="utf-8", errors="ignore") as f:
                    first_line = f.readline()

                scrubbed_first_line = self._scrub_content(first_line, base_name, logger)

                if (scrubbed_first_line != first_line or self.decompress) and not dry_run:
                    with lzma.open(file_path, mode="rt", encoding="utf-8", errors="ignore") as f:
                        f.readline()
                        rest = f.read()
                    plain_path = file_path[:-3]
                    header = _SCRUB_INFO_HEADER if scrubbed_first_line != first_line else ""
                    with open(plain_path, mode="w", encoding="utf-8") as out_f:
                        out_f.write(header + scrubbed_first_line + rest)
                    os.remove(file_path)

            elif is_sar_plain_file:
                with open(file_path, mode="r", encoding="utf-8", errors="ignore") as f:
                    first_line = f.readline()
                    rest = f.read()

                scrubbed_first_line = self._scrub_content(first_line, base_name, logger)

                if scrubbed_first_line != first_line and not dry_run:
                    with open(file_path, mode="w", encoding="utf-8") as out_f:
                        out_f.write(_SCRUB_INFO_HEADER + scrubbed_first_line + rest)

            elif compressed_opener(base_name):
                ext, opener = compressed_opener(base_name)
                with opener(file_path, mode="rt", encoding="utf-8", errors="ignore") as f:
                    original_text = f.read()

                # Strip the compression extension so per-file skip lists
                # (e.g. MAC skipping modules.txt) still apply.
                scrubbed_text = self._scrub_content(original_text, base_name[:-len(ext)], logger)

                plain_path = file_path[:-len(ext)]
                # A plain sibling (boot.log next to boot.log.gz) must not be
                # overwritten by the decompressed copy; keep such files
                # compressed instead.
                if self.decompress and not dry_run and not os.path.exists(plain_path):
                    header = _SCRUB_INFO_HEADER if scrubbed_text != original_text else ""
                    with open(plain_path, mode="w", encoding="utf-8") as out_f:
                        out_f.write(header + scrubbed_text)
                    os.remove(file_path)
                elif scrubbed_text != original_text and not dry_run:
                    with opener(file_path, mode="wt", encoding="utf-8") as out_f:
                        out_f.write(_SCRUB_INFO_HEADER + scrubbed_text)

            else:
                with open(file_path, mode="r", encoding="utf-8", errors="ignore") as file:
                    original_text = file.read()

                scrubbed_text = self._scrub_content(original_text, base_name, logger)

                if scrubbed_text != original_text and not dry_run:
                    with open(file_path, mode="w", encoding="utf-8") as out_f:
                        out_f.write(_SCRUB_INFO_HEADER + scrubbed_text)

        except Exception as e:
            logger.error(f"Error processing file {file_path}: {str(e)}")

    def _scrub_content(self, text, basename, logger):
        if self.learn_only:
            for scrubber in self.scrubbers:
                gate = _CONFIG_GATES.get(scrubber.name)
                if gate and not gate(self.config):
                    continue
                if scrubber.skip_files and basename in scrubber.skip_files:
                    continue
                try:
                    learn = getattr(scrubber, 'learn', None)
                    if learn is not None:
                        learn(text)
                    else:
                        scrubber.scrub(text)
                except Exception as e:
                    logger.error(f"{scrubber.name} learn failed for {basename}: {e}")
            return text

        if not self.profile:
            for scrubber in self.scrubbers:
                gate = _CONFIG_GATES.get(scrubber.name)
                if gate and not gate(self.config):
                    continue
                if scrubber.skip_files and basename in scrubber.skip_files:
                    continue
                try:
                    text = scrubber.scrub(text)
                except Exception as e:
                    logger.error(f"{scrubber.name} scrub failed for {basename}: {e}")
            return text

        nbytes = len(text)
        file_total = 0.0
        for scrubber in self.scrubbers:
            gate = _CONFIG_GATES.get(scrubber.name)
            if gate and not gate(self.config):
                continue
            if scrubber.skip_files and basename in scrubber.skip_files:
                continue
            t0 = time.perf_counter()
            try:
                text = scrubber.scrub(text)
            except Exception as e:
                logger.error(f"{scrubber.name} scrub failed for {basename}: {e}")
            dt = time.perf_counter() - t0
            file_total += dt
            rec = self.prof.setdefault(scrubber.name, {'time': 0.0, 'bytes': 0, 'calls': 0})
            rec['time'] += dt
            rec['bytes'] += nbytes
            rec['calls'] += 1
        if file_total > 0:
            self.file_prof.append((basename, file_total, nbytes))
        return text

    def process_text(self, text, logger, verbose_flag):
        return self._scrub_content(text, "stdin", logger)
