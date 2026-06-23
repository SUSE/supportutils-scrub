# extractor.py

import os
import shutil
import logging
import tarfile
import subprocess


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
        for file in files:
            report_files.append(os.path.join(root, file))
    return report_files

def extract_xz_archive(archive_path, logger, extract_base=None):
    """
    Extract an XZ archive and return a list of report files.
    """
    base_name = os.path.basename(archive_path)
    base_name_no_ext = os.path.splitext(base_name)[0]
    clean_folder_name = base_name_no_ext + "_scrubbed"
    if extract_base:
        clean_folder_path = os.path.join(extract_base, clean_folder_name)
    else:
        clean_folder_path = os.path.join(os.path.dirname(archive_path), clean_folder_name)

    if os.path.exists(clean_folder_path):
        shutil.rmtree(clean_folder_path)

    os.makedirs(clean_folder_path, exist_ok=True) 

    with tarfile.open(archive_path, 'r:xz') as tar:
        members = tar.getmembers()
        top_level = None
        for member in members:
            top = member.name.split('/')[0]
            if top:
                top_level = top
                break

        for member in members:
            if member.issym() or member.islnk():
                continue
            if member.isdir():
                continue
            if top_level and member.name.startswith(top_level + '/'):
                relative_path = member.name[len(top_level) + 1:]
            else:
                relative_path = os.path.basename(member.name)
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

def extract_tgz_archive(archive_path, logger, extract_base=None, mode="r:gz"):
    """Extract a tar archive (gz/bz2/xz per `mode`) and return report files."""
    archive_dir = os.path.dirname(archive_path)
    base_name = os.path.basename(archive_path)
    base_name_no_ext = strip_archive_ext(base_name)
    clean_folder_name = base_name_no_ext + "_scrubbed"
    if extract_base:
        clean_folder_path = os.path.join(extract_base, clean_folder_name)
        tar_extract_base = extract_base
    else:
        clean_folder_path = os.path.join(archive_dir, clean_folder_name)
        tar_extract_base = archive_dir

    if os.path.exists(clean_folder_path):
        shutil.rmtree(clean_folder_path)

    os.makedirs(clean_folder_path, exist_ok=True)

    with tarfile.open(archive_path, mode) as tar:
        members = tar.getmembers()
        top_level = None
        for member in members:
            top = member.name.split('/')[0]
            if top:
                top_level = top
                break

        for member in members:
            if member.issym() or member.islnk():
                continue
            if member.isdir():
                continue

            if top_level and member.name.startswith(top_level + '/'):
                relative_path = member.name[len(top_level) + 1:]
            else:
                relative_path = os.path.basename(member.name)

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
    """copy folder_path to {folder_path}_scrubbed/ and return (file_list, scrubbed_path) """
    scrubbed_path = folder_path.rstrip('/') + '_scrubbed'
    if os.path.exists(scrubbed_path):
        shutil.rmtree(scrubbed_path)
    shutil.copytree(folder_path, scrubbed_path)
    return walk_supportconfig(scrubbed_path), scrubbed_path
