# extractor.py

import os
import shutil
import logging
import tarfile 

def extract_supportconfig(supportconfig_path, logger):
    """
    Extract Supportconfig files and return a list of  files.
    """
    report_files = []
    
    if os.path.isdir(supportconfig_path):
        # Supportconfig is a folder
        report_files = walk_supportconfig(supportconfig_path)
    elif supportconfig_path.endswith(".txz"):
        report_files = extract_xz_archive(supportconfig_path, logger)
    elif supportconfig_path.endswith(".tgz"):
        report_files = extract_tgz_archive(supportconfig_path, logger)
    else:
        logging.error(f"Unsupported file type: {supportconfig_path}")
        raise Exception(f"Unsupported file type: {supportconfig_path}")

    logging.info(f"Extraction successful. Return path: {supportconfig_path}")
    return report_files

def walk_supportconfig(folder_path):
    """
    Walk through the Supportconfig folder and return a list of report files.
    """
    report_files = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".txt"):
                report_files.append(os.path.join(root, file))
    return report_files

def extract_xz_archive(archive_path, logger):
    """
    Extract an XZ archive and return a list of report files.
    """
    extract_base_folder = os.path.dirname(archive_path)
    base_name = os.path.basename(archive_path)
    base_name_no_ext = os.path.splitext(base_name)[0]
    clean_folder_name = base_name_no_ext + "_scrubbed"
    clean_folder_path = os.path.join(extract_base_folder, clean_folder_name)

    if os.path.exists(clean_folder_path):
        shutil.rmtree(clean_folder_path)

    with tarfile.open(archive_path, 'r:xz') as tar:
        members = tar.getmembers()
        for member in members:
            member.name = os.path.join(clean_folder_name, os.path.basename(member.name))
            tar.extract(member, path=extract_base_folder)
    
    report_files = walk_supportconfig(clean_folder_path)
    logger.info(f"Extracted .txz to: {clean_folder_path}")

    return report_files, clean_folder_path

def extract_tgz_archive(archive_path, logger):
    """Extract a .tgz (tar gzipped) archive and return a list of report files."""
    extract_base_folder = os.path.dirname(archive_path)
    base_name = os.path.basename(archive_path)
    base_name_no_ext = os.path.splitext(base_name)[0]
    clean_folder_name = base_name_no_ext + "_scrubbed"
    clean_folder_path = os.path.join(extract_base_folder, clean_folder_name)

    if os.path.exists(clean_folder_path):
        shutil.rmtree(clean_folder_path)

    with tarfile.open(archive_path, "r:gz") as tar:
        members = tar.getmembers()
        for member in members:
            member.name = os.path.join(clean_folder_name, os.path.basename(member.name))
            tar.extract(member, path=extract_base_folder)

    report_files = walk_supportconfig(clean_folder_path)
    logger.info(f"Extracted .tgz to: {clean_folder_path}")
    return report_files, clean_folder_path

def create_txz(source_dir, output_filename):
    with tarfile.open(output_filename, 'w:xz') as tar:
        tar.add(source_dir, arcname=os.path.basename(source_dir))
