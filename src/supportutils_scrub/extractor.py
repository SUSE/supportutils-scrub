# extractor.py

import os
import shutil
import logging
import tarfile
import subprocess

from supportutils_scrub.processor import append_scrubbed


_ARCHIVE_SUFFIXES = ('.tar.gz', '.tar.bz2', '.tar.xz', '.tgz', '.tbz', '.tbz2', '.txz')


def strip_archive_ext(name: str) -> str:
    """Strip a tar archive extension (handles double extensions like .tar.bz2)."""
    low = name.lower()
    for suf in _ARCHIVE_SUFFIXES:
        if low.endswith(suf):
            return name[:-len(suf)]
    return os.path.splitext(name)[0]


def is_archive_path(path: str) -> bool:
    return path.lower().endswith(_ARCHIVE_SUFFIXES)


def _common_top_level(members):
    """The single top-level directory that contains EVERY file member, or None.

    Only such a genuine wrapper (the scc_host_date/ folder of a normal
    supportconfig archive) may be stripped on extraction. The old logic took
    the FIRST member's first path component and basename-flattened every
    member that did not match it, so a multi-root archive (e.g. a bundle
    packed without a wrapper: spacewalk-debug/..., conf/..., logs) lost its
    whole directory structure on extract.
    """
    tops = set()
    for m in members:
        name = (m.name or "").strip("/")
        if not name:
            continue
        if "/" not in name:
            if m.isdir():
                tops.add(name)
                continue
            return None          # a file at the archive root: nothing to strip
        tops.add(name.split("/", 1)[0])
    return tops.pop() if len(tops) == 1 else None


def _member_relative_path(member, top_level):
    """Extraction path for a member: wrapper stripped when one exists,
    the member's own path PRESERVED otherwise (never basename-flattened)."""
    name = (member.name or "").lstrip("/")
    if top_level and name.startswith(top_level + "/"):
        return name[len(top_level) + 1:]
    return name


def _is_safe_path(target_dir: str, member_name: str) -> bool:
    """Return True if member_name extracts safely within target_dir."""
    norm = os.path.normpath(member_name)
    if os.path.isabs(norm) or norm.startswith('..'):
        return False
    target = os.path.realpath(target_dir)
    dest   = os.path.realpath(os.path.join(target_dir, member_name))
    return dest.startswith(target + os.sep) or dest == target

def extract_supportconfig(supportconfig_path, logger, extract_base=None):
    """Extract Supportconfig files and return a list of  file """
    report_files = []

    low = supportconfig_path.lower()
    if os.path.isdir(supportconfig_path):
        report_files = walk_supportconfig(supportconfig_path)
    elif low.endswith(".txz") or low.endswith(".tar.xz"):
        report_files = extract_tgz_archive(supportconfig_path, logger, extract_base=extract_base, mode="r:xz")
    elif low.endswith(".tgz") or low.endswith(".tar.gz"):
        report_files = extract_tgz_archive(supportconfig_path, logger, extract_base=extract_base, mode="r:gz")
    elif low.endswith(".tbz") or low.endswith(".tbz2") or low.endswith(".tar.bz2"):
        report_files = extract_tgz_archive(supportconfig_path, logger, extract_base=extract_base, mode="r:bz2")
    else:
        print(f"[!] Unsupported file type: {supportconfig_path}")
        raise Exception(f"Unsupported file type: {supportconfig_path}")
    return report_files

def walk_supportconfig(folder_path):
    """ Walk through the Supportconfig folder and return a list of all files """
    report_files = []
    for root, dirs, files in os.walk(folder_path):
        # Sorted: fake values are allocated in first-seen order, and two
        # copies of one tree list their entries in different inode orders.
        # A sorted walk makes the mapping a pure function of the content.
        dirs.sort()
        for file in sorted(files):
            report_files.append(os.path.join(root, file))
    return report_files


# Nested archives also include plain .tar; tarfile 'r:*' auto-detects.
_NESTED_ARCHIVE_SUFFIXES = _ARCHIVE_SUFFIXES + ('.tar',)


def expand_nested_archives(root_dir, logger=None, max_depth=5):
    """Unpack tar archives found anywhere under root_dir so their contents get
    scrubbed like regular files. Each archive is extracted into a sibling
    folder named after it (extension stripped) and then removed — the output
    stays unpacked. Repeats up to max_depth times for archives-in-archives.
    An archive that cannot be unpacked is removed too: shipping it unscrubbed
    would leak whatever it contains. Returns the number of archives unpacked.
    """
    unpacked = 0
    for _ in range(max_depth):
        archives = [p for p in walk_supportconfig(root_dir)
                    if p.lower().endswith(_NESTED_ARCHIVE_SUFFIXES)]
        if not archives:
            break
        for archive in archives:
            rel = os.path.relpath(archive, root_dir)
            dest = os.path.join(os.path.dirname(archive),
                                strip_archive_ext(os.path.basename(archive)))
            base_dest, n = dest, 1
            while os.path.exists(dest):
                dest = f"{base_dest}_{n}"
                n += 1
            try:
                with tarfile.open(archive, 'r:*') as tar:
                    os.makedirs(dest)
                    for member in tar.getmembers():
                        # Untrusted content: regular files and dirs only, no
                        # symlinks/devices, no paths escaping dest.
                        if not (member.isfile() or member.isdir()):
                            continue
                        if not _is_safe_path(dest, member.name):
                            continue
                        tar.extract(member, path=dest)
                if logger:
                    logger.info(f"Unpacked nested archive: {rel}")
                unpacked += 1
            except Exception as e:
                if logger:
                    logger.error(f"Could not unpack nested archive {rel}: {e} — removed (cannot scrub its contents)")
            try:
                os.remove(archive)
            except OSError as e:
                if logger:
                    logger.error(f"Failed to remove nested archive {rel}: {e}")
    return unpacked

def extract_xz_archive(archive_path, logger, extract_base=None):
    """
    Extract an XZ archive and return a list of report files.
    """
    base_name = os.path.basename(archive_path)
    base_name_no_ext = os.path.splitext(base_name)[0]
    clean_folder_name = append_scrubbed(base_name_no_ext)
    if extract_base:
        clean_folder_path = os.path.join(extract_base, clean_folder_name)
    else:
        clean_folder_path = os.path.join(os.path.dirname(archive_path), clean_folder_name)

    if os.path.exists(clean_folder_path):
        shutil.rmtree(clean_folder_path)

    os.makedirs(clean_folder_path, exist_ok=True) 

    with tarfile.open(archive_path, 'r:xz') as tar:
        members = tar.getmembers()
        top_level = _common_top_level(members)

        for member in members:
            if member.issym() or member.islnk():
                continue
            if member.isdir():
                continue
            relative_path = _member_relative_path(member, top_level)
            if not relative_path:
                continue
            if not _is_safe_path(clean_folder_path, relative_path):
                print(f"[!] Blocked unsafe path in archive: {member.name}")
                continue
            member.name = relative_path
            try:
                tar.extract(member, path=clean_folder_path)
            except Exception as e:
                print(f"[!] Error extracting {member.name}: {e}")

    report_files = walk_supportconfig(clean_folder_path)
    if extract_base:
        print(f"[✓] Archive extracted to RAM (tmpfs): {clean_folder_path}")
    else:
        print(f"[✓] Archive extracted to: {clean_folder_path}")

    return report_files, clean_folder_path

# Extraction through a multi-threaded decompressor when one is installed:
# Python's lzma/gzip/bz2 modules are single-threaded, and on a 128-core box
# the extract phase ran on one of them (22 s p99) while the repack already
# streamed through `xz -T0`. The tar is parsed by tarfile in stream mode, so
# wrapper stripping and the traversal guard are the same code as before.
_EXTERNAL_DECOMPRESS = True
_DECOMPRESSORS = {
    'r:xz': (['xz', '-T0', '-dc'], ['xz']),
    'r:gz': (['pigz', '-dc'], ['pigz']),
    'r:bz2': (['pbzip2', '-dc'], ['pbzip2']),
}


def _decompressor_cmd(mode):
    """The external decompressor command for `mode`, or None."""
    if not _EXTERNAL_DECOMPRESS:
        return None
    entry = _DECOMPRESSORS.get(mode)
    if not entry:
        return None
    cmd, need = entry
    return cmd if all(shutil.which(b) for b in need) else None


def _stream_members(archive_path, cmd):
    """Yield (tar, member) over a tar stream fed by `cmd`; the tar object is
    needed to extract the current member. Caller consumes strictly in order."""
    with open(archive_path, 'rb') as src:
        proc = subprocess.Popen(cmd, stdin=src, stdout=subprocess.PIPE)
        try:
            with tarfile.open(fileobj=proc.stdout, mode='r|') as tar:
                for member in tar:
                    yield tar, member
        finally:
            proc.stdout.close()
            if proc.wait() != 0:
                raise RuntimeError(f"{cmd[0]} exited with status {proc.returncode}")


def _extract_streaming(archive_path, cmd, clean_folder_path, clean_folder_name,
                       tar_extract_base):
    """Two streamed passes: the first learns the member list (the wrapper
    decision needs all of it), the second extracts. Decompression runs in
    the external tool, multi-threaded, both times."""
    members = [m for _tar, m in _stream_members(archive_path, cmd)]
    top_level = _common_top_level(members)
    for tar, member in _stream_members(archive_path, cmd):
        if member.issym() or member.islnk() or member.isdir():
            continue
        relative_path = _member_relative_path(member, top_level)
        if not relative_path:
            continue
        if not _is_safe_path(clean_folder_path, relative_path):
            print(f"[!] Blocked unsafe path in archive: {member.name}")
            continue
        member.name = os.path.join(clean_folder_name, relative_path)
        try:
            tar.extract(member, path=tar_extract_base)
        except Exception as e:
            logging.warning(f"Skipping {member.name}: {e}")


def extract_tgz_archive(archive_path, logger, extract_base=None, mode="r:gz"):
    """Extract a tar archive (gz/bz2/xz per `mode`) and return report files."""
    archive_dir = os.path.dirname(archive_path)
    base_name = os.path.basename(archive_path)
    base_name_no_ext = strip_archive_ext(base_name)
    clean_folder_name = append_scrubbed(base_name_no_ext)
    if extract_base:
        clean_folder_path = os.path.join(extract_base, clean_folder_name)
        tar_extract_base = extract_base
    else:
        clean_folder_path = os.path.join(archive_dir, clean_folder_name)
        tar_extract_base = archive_dir

    if os.path.exists(clean_folder_path):
        shutil.rmtree(clean_folder_path)

    os.makedirs(clean_folder_path, exist_ok=True)

    cmd = _decompressor_cmd(mode)
    if cmd:
        try:
            _extract_streaming(archive_path, cmd, clean_folder_path,
                               clean_folder_name, tar_extract_base)
            report_files = walk_supportconfig(clean_folder_path)
            print(f"[✓] Archive extracted ({cmd[0]}, multi-threaded) to: "
                  f"{clean_folder_path}")
            return report_files, clean_folder_path
        except Exception as e:
            # the Python path below is the fallback for anything the stream
            # cannot do; start over from an empty folder
            logging.warning(f"streaming extraction failed ({e}); "
                            "falling back to the Python extractor")
            shutil.rmtree(clean_folder_path, ignore_errors=True)
            os.makedirs(clean_folder_path, exist_ok=True)

    with tarfile.open(archive_path, mode) as tar:
        members = tar.getmembers()
        top_level = _common_top_level(members)

        for member in members:
            if member.issym() or member.islnk():
                continue
            if member.isdir():
                continue

            relative_path = _member_relative_path(member, top_level)

            if not relative_path:
                continue

            if not _is_safe_path(clean_folder_path, relative_path):
                print(f"[!] Blocked unsafe path in archive: {member.name}")
                continue

            member.name = os.path.join(clean_folder_name, relative_path)
            try:
                tar.extract(member, path=tar_extract_base)
            except Exception as e:
                logging.warning(f"Skipping {member.name}: {e}")

    report_files = walk_supportconfig(clean_folder_path)
    if extract_base:
        print(f"[✓] Archive extracted to RAM (tmpfs): {clean_folder_path}")
    else:
        print(f"[✓] Archive extracted to: {clean_folder_path}")
    return report_files, clean_folder_path

def create_txz(source_dir, output_filename):
    xz_bin = shutil.which('xz')
    if xz_bin:
        # Stream an uncompressed tar into multithreaded `xz -T0` so all cores
        # are used. Python's lzma module is single-threaded; on a large
        # supportconfig this compression step dominates the runtime.
        with open(output_filename, 'wb') as out_f:
            proc = subprocess.Popen([xz_bin, '-T0', '-c'],
                                    stdin=subprocess.PIPE, stdout=out_f)
            try:
                with tarfile.open(fileobj=proc.stdin, mode='w|') as tar:
                    tar.add(source_dir, arcname=os.path.basename(source_dir))
            finally:
                proc.stdin.close()
                ret = proc.wait()
            if ret != 0:
                raise RuntimeError(f"xz exited with status {ret} while writing {output_filename}")
        return

    # Fallback: no xz binary available, use single-threaded lzma.
    with tarfile.open(output_filename, 'w:xz') as tar:
        tar.add(source_dir, arcname=os.path.basename(source_dir))

def copy_folder_to_scrubbed(folder_path):
    """copy folder_path to {folder_path}_scrubbed/ and return (file_list, scrubbed_path)

    A folder already named *_scrubbed is re-scrubbed in place instead of
    copied onto itself."""
    src = folder_path.rstrip('/')
    scrubbed_path = append_scrubbed(src)
    if scrubbed_path == src:
        return walk_supportconfig(scrubbed_path), scrubbed_path
    if os.path.exists(scrubbed_path):
        shutil.rmtree(scrubbed_path)

    # Copying is I/O-bound and copyfile releases the GIL (sendfile), so a
    # small thread pool beats copytree's one-file-at-a-time walk. Unreadable
    # files are skipped with a warning, same net effect as copytree's
    # collected shutil.Error.
    from concurrent.futures import ThreadPoolExecutor
    tasks = []
    for root, dirs, files in os.walk(src):
        rel = os.path.relpath(root, src)
        dst_root = scrubbed_path if rel == '.' else os.path.join(scrubbed_path, rel)
        os.makedirs(dst_root, exist_ok=True)
        for f in files:
            tasks.append((os.path.join(root, f), os.path.join(dst_root, f)))

    errors = []
    workers = min(16, max(4, os.cpu_count() or 4))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(shutil.copy2, s, d) for s, d in tasks]
        for (s, _), fut in zip(tasks, futures):
            try:
                fut.result()
            except OSError as e:
                errors.append((s, e))
    for s, e in errors[:5]:
        print(f"[!] Could not copy {s}: {e}")
    if len(errors) > 5:
        print(f"[!] ... and {len(errors) - 5} more files could not be copied")
    shutil.copystat(src, scrubbed_path)
    return walk_supportconfig(scrubbed_path), scrubbed_path
