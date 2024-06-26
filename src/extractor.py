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
    unpack_folder = shutil.unpack_archive(archive_path, extract_base_folder)
    supportconfig_folder = os.path.splitext(archive_path)[0]
    report_files = walk_supportconfig(supportconfig_folder)
    logger.info(f"Extracted .txz to: {supportconfig_folder}")

    return report_files

def extract_tgz_archive(archive_path, logger):
    """Extract a .tgz (tar gzipped) archive and return a list of report files."""
    extract_base_folder = os.path.dirname(archive_path)
    with tarfile.open(archive_path, "r:gz") as tar:
        tar.extractall(path=extract_base_folder)
        # Assuming the first member is the root directory
        root_directory = tar.getmembers()[0].name.split('/')[0]
    supportconfig_folder = os.path.join(extract_base_folder, root_directory)
    logger.info(f"Extracted .tgz to: {supportconfig_folder}")
    report_files = walk_supportconfig(supportconfig_folder)
    return report_files