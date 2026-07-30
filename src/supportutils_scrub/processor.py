# processor.py

import os
import bz2
import gzip
import lzma
import re
import time
import zlib
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
_COMPRESS_MAGIC = {'.gz': b'\x1f\x8b', '.xz': b'\xfd7zXZ\x00', '.bz2': b'BZh'}

# How much of a decompressed payload is inspected for NUL bytes before deciding
# it is binary and must not be text-scrubbed.
_TEXT_PROBE = 64 * 1024
_READ_CHUNK = 1024 * 1024


def compressed_opener(base_name):
    """Return (ext, open_func) for single-file compressed names, else None."""
    low = base_name.lower()
    if low.endswith(_TAR_SUFFIXES):
        return None
    for ext, opener in _COMPRESS_OPENERS.items():
        if low.endswith(ext):
            return ext, opener
    return None


def compression_magic_ok(path, ext=None):
    """True when a file starts with the stream its extension declares.

    A name carrying no single-file compression extension is trivially OK."""
    if ext is None:
        comp = compressed_opener(os.path.basename(path))
        if not comp:
            return True
        ext = comp[0]
    magic = _COMPRESS_MAGIC[ext]
    try:
        with open(path, 'rb') as f:
            return f.read(len(magic)) == magic
    except OSError:
        return False


def find_format_mismatches(root):
    """Files under root whose name declares .gz/.xz/.bz2 but whose content is
    not that stream. Returns [(path, ext)].

    A scrub run must never leave one behind: a consumer that follows the
    extension gets a decoder error and skips the file, so its content silently
    disappears from the analysable set."""
    bad = []
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            comp = compressed_opener(name)
            if not comp:
                continue
            path = os.path.join(dirpath, name)
            if not compression_magic_ok(path, comp[0]):
                bad.append((path, comp[0]))
    return bad


def _salvage_decompressed(path, ext):
    """Bytes recoverable from a damaged stream: feed the raw file to an
    incremental decompressor and keep whatever it produced before it gave up.
    The stream openers discard their pending output when they hit the bad tail,
    so this is what keeps a truncated log scrubbable instead of untouchable."""
    if ext == '.gz':
        dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif ext == '.xz':
        dec = lzma.LZMADecompressor()
    else:
        dec = bz2.BZ2Decompressor()
    out = []
    try:
        with open(path, 'rb') as f:
            while True:
                block = f.read(_READ_CHUNK)
                if not block:
                    break
                out.append(dec.decompress(block))
                if getattr(dec, 'eof', False):
                    break
    except Exception:
        pass
    if ext == '.gz':
        try:
            out.append(dec.flush())
        except Exception:
            pass
    return b''.join(out)


def looks_binary(path):
    """True when a file's head holds NUL bytes, i.e. it is not text."""
    try:
        with open(path, 'rb') as f:
            return b'\x00' in f.read(_TEXT_PROBE)
    except OSError:
        return False


def read_compressed_text(path, ext, opener):
    """Decompress path and return (text, status):

        'ok'           text is the whole payload
        'truncated'    the stream ends early; text is what could be salvaged
        'not-a-stream' the name lies about the content; text is None
        'binary'       a valid stream, but the payload is not text; text is None

    Decoding uses surrogateescape so bytes that are not valid UTF-8 (a log line
    in some other encoding) survive the round trip instead of being dropped."""
    if not compression_magic_ok(path, ext):
        return None, 'not-a-stream'
    chunks = []
    status = 'ok'
    try:
        with opener(path, 'rb') as f:
            while True:
                chunk = f.read(_READ_CHUNK)
                if not chunk:
                    break
                chunks.append(chunk)
        data = b''.join(chunks)
    except Exception:
        # Damaged tail: keep what does decompress. The rest is unreadable for
        # every consumer anyway, and scrubbing the readable prefix beats
        # shipping it raw.
        status = 'truncated'
        data = _salvage_decompressed(path, ext)
    if b'\x00' in data[:_TEXT_PROBE]:
        return None, 'binary'
    return data.decode('utf-8', 'surrogateescape'), status


def write_compressed_text(path, ext, opener, text, logger, label=None):
    """Compress text back into path, atomically, and prove the result is a
    complete readable stream before it replaces the original.

    Returns True on success. On any failure path keeps its previous content and
    the reason is logged — a rewrite can never silently turn a compressed file
    into something that is not one."""
    label = label or os.path.basename(path)
    data = text.encode('utf-8', 'surrogateescape')
    tmp = path + '.scrubtmp'
    try:
        if ext == '.gz':
            # gzip stores the original name in the header; writing through
            # gzip.open(tmp) would record the temporary name.
            with open(tmp, 'wb') as fh:
                with gzip.GzipFile(filename=os.path.basename(path)[:-len(ext)],
                                   mode='wb', fileobj=fh) as out:
                    out.write(data)
        else:
            with opener(tmp, 'wb') as out:
                out.write(data)

        read_back = 0
        with opener(tmp, 'rb') as check:
            while True:
                chunk = check.read(_READ_CHUNK)
                if not chunk:
                    break
                read_back += len(chunk)
        if read_back != len(data):
            raise ValueError(f"read back {read_back} of {len(data)} bytes")
        if not compression_magic_ok(tmp, ext):
            raise ValueError(f"result is not a {ext[1:]} stream")

        os.replace(tmp, path)
        return True
    except Exception as e:
        logger.error(f"{label}: left unchanged, could not write a valid "
                     f"{ext[1:]} stream: {e}")
        try:
            os.remove(tmp)
        except OSError:
            pass
        return False


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
                self._process_compressed(file_path, base_name, ext, opener, logger, dry_run)

            else:
                self._process_plain(file_path, base_name, logger, dry_run)

        except Exception as e:
            logger.error(f"Error processing file {file_path}: {str(e)}")

    def _process_plain(self, file_path, base_name, logger, dry_run):
        with open(file_path, mode="r", encoding="utf-8", errors="ignore") as file:
            original_text = file.read()

        scrubbed_text = self._scrub_content(original_text, base_name, logger)

        if scrubbed_text != original_text and not dry_run:
            with open(file_path, mode="w", encoding="utf-8") as out_f:
                out_f.write(_SCRUB_INFO_HEADER + scrubbed_text)

    def _process_compressed(self, file_path, base_name, ext, opener, logger, dry_run):
        """Scrub a single-file compressed log, keeping name and content in
        agreement: what goes back under a .gz/.xz/.bz2 name is always a valid
        stream of that format, or the file is not rewritten at all."""
        original_text, status = read_compressed_text(file_path, ext, opener)
        # The parallel discovery pre-pass sees every file a second time; only
        # the pass that actually writes reports what it found.
        warn = logger.error if not dry_run else lambda msg: None

        if status == 'binary':
            warn(f"{base_name}: {ext[1:]} payload is not text — left unchanged "
                 f"(text-scrubbing it would destroy the payload)")
            return

        if status == 'not-a-stream':
            if looks_binary(file_path):
                # Some other binary format under this name. Rewriting it as
                # text would destroy it, so leave it for the tree-wide
                # mismatch report to name.
                warn(f"{base_name}: neither a {ext[1:]} stream nor text — left unchanged")
                return
            # The extension promises a stream the content does not have. Scrub
            # it as the plain text it really is, then drop the misleading
            # extension so consumers that follow the name can read it.
            warn(f"{base_name}: not a {ext[1:]} stream despite the extension — "
                 f"scrubbed as plain text")
            self._process_plain(file_path, base_name, logger, dry_run)
            if dry_run:
                return
            plain_path = file_path[:-len(ext)]
            if os.path.exists(plain_path):
                logger.error(f"{base_name}: misleading name kept, "
                             f"{os.path.basename(plain_path)} already exists")
            else:
                os.rename(file_path, plain_path)
            return

        if status == 'truncated' and not original_text:
            warn(f"{base_name}: {ext[1:]} stream is damaged and nothing could be "
                 f"decompressed — left as it is, its content is NOT scrubbed")
            return
        if status == 'truncated':
            warn(f"{base_name}: {ext[1:]} stream ends before its end-of-stream "
                 f"marker — rewritten from the {len(original_text)} bytes that could "
                 f"be salvaged, the damaged tail is dropped")

        # Strip the compression extension so per-file skip lists
        # (e.g. MAC skipping modules.txt) still apply.
        scrubbed_text = self._scrub_content(original_text, base_name[:-len(ext)], logger)
        if dry_run:
            return

        plain_path = file_path[:-len(ext)]
        # A plain sibling (boot.log next to boot.log.gz) must not be
        # overwritten by the decompressed copy; keep such files
        # compressed instead.
        if self.decompress and not os.path.exists(plain_path):
            header = _SCRUB_INFO_HEADER if scrubbed_text != original_text else ""
            with open(plain_path, mode="w", encoding="utf-8",
                      errors="surrogateescape") as out_f:
                out_f.write(header + scrubbed_text)
            os.remove(file_path)
        elif scrubbed_text != original_text or status == 'truncated':
            # A damaged file is rewritten even when nothing matched: what ships
            # is then a complete stream of content the scrubbers have seen, not
            # a tail no consumer can read and no scrubber has checked.
            write_compressed_text(file_path, ext, opener,
                                  _SCRUB_INFO_HEADER + scrubbed_text, logger, base_name)

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
