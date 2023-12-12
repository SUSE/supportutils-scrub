# scrubber/extractor.py

import os
import shutil

def extract_supportconfig(supportconfig_path):
    """
    Extract Supportconfig files and return a list of  files.
    """
    report_files = []
    
    if os.path.isdir(supportconfig_path):
        # Supportconfig is a folder
        report_files = walk_supportconfig(supportconfig_path)
    elif supportconfig_path.endswith(".txz"):
        # Supportconfig is an XZ archive
        report_files = extract_xz_archive(supportconfig_path)
    else:
        raise Exception(f"Unsupported file type: {supportconfig_path}")

    print(f"Extraction successful. Return path: {supportconfig_path}")
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

def extract_xz_archive(archive_path):
    """
    Extract an XZ archive and return a list of report files.
    """
    extract_base_folder = os.path.dirname(archive_path)
    unpack_folder = shutil.unpack_archive(archive_path, extract_base_folder)
    supportconfig_folder = os.path.splitext(archive_path)[0]
    report_files = walk_supportconfig(supportconfig_folder)
    return report_files

