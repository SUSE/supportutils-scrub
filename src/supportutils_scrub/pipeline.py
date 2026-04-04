# pipeline.py — shared extraction, mapping, and scrubber-init helpers

import os
import sys
import re
import logging
import shutil
from supportutils_scrub.config import DEFAULT_CONFIG_PATH
from supportutils_scrub.ip_scrubber import IPScrubber
from supportutils_scrub.domain_scrubber import DomainScrubber
from supportutils_scrub.hostname_scrubber import HostnameScrubber
from supportutils_scrub.keyword_scrubber import KeywordScrubber
from supportutils_scrub.username_scrubber import UsernameScrubber
from supportutils_scrub.mac_scrubber import MACScrubber
from supportutils_scrub.ipv6_scrubber import IPv6Scrubber
from supportutils_scrub.serial_scrubber import SerialScrubber
from supportutils_scrub.audit import load_mappings_file


def warn_private_ip(config, file=None):
    out = file or sys.stdout
    if not config.obfuscate_private_ip:
        print("[!] WARNING: Private IP obfuscation is DISABLED.", file=out)
        print("    Only public IP addresses will be obfuscated.", file=out)
        print(f"    To also obfuscate private IPs (10.x, 172.16.x, 192.168.x),", file=out)
        print(f"    set 'obfuscate_private_ip = yes' in {DEFAULT_CONFIG_PATH}", file=out)
        print(file=out)


def _next_fake_tld(counter):
    letters = 'abcdefghijklmnopqrstuvwxyz'
    a, b, c = counter // 676, (counter // 26) % 26, counter % 26
    return letters[a] + letters[b] + letters[c]


def build_hierarchical_domain_map(all_domains, existing_mappings):
    valid_domains = {d for d in all_domains if '.' in d}
    sorted_domains = sorted(list(valid_domains), key=lambda d: len(d.split('.')))

    domain_dict = existing_mappings.get('domain', {})
    tld_map = existing_mappings.get('tld_map', {})
    base_domain_counter = len(domain_dict)
    sub_domain_counter = 0

    for domain in sorted_domains:
        if domain in domain_dict:
            continue
        parts = domain.split('.')
        parent_domain = '.'.join(parts[1:])

        if parent_domain in domain_dict:
            obfuscated_sub_part = f"sub_{sub_domain_counter}"
            sub_domain_counter += 1
            domain_dict[domain] = f"{obfuscated_sub_part}.{domain_dict[parent_domain]}"
        else:
            real_tld = parts[-1].lower()
            if real_tld not in tld_map:
                tld_map[real_tld] = _next_fake_tld(len(tld_map))
            fake_tld = tld_map[real_tld]
            domain_dict[domain] = f"domain_{base_domain_counter}.{fake_tld}"
            base_domain_counter += 1

    return domain_dict, tld_map


def extract_and_map_domains(report_files, additional_domains, mappings):
    all_domains = set()
    for domain in additional_domains:
        DomainScrubber._add_domain_and_parents(domain, all_domains)

    files_to_scan = {
        'network.txt': ['# /etc/hosts', '# /etc/resolv.conf'],
        'nfs.txt': ['# /bin/egrep'],
        'ntp.txt': ['# /etc/ntp.conf', '# /etc/chrony.conf'],
        'sssd.txt': ['# /etc/sssd/sssd.conf'],
    }
    for file_path in report_files:
        basename = os.path.basename(file_path)
        if basename in files_to_scan:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for section in files_to_scan[basename]:
                        domains = DomainScrubber.extract_domains_from_file_section(f, section)
                        all_domains.update(domains)
            except Exception as e:
                logging.error(f"Error reading file {file_path}: {e}")

    return build_hierarchical_domain_map(all_domains, mappings)


def extract_hostnames(report_files, additional_hostnames, mappings):
    hostname_dict = mappings.get('hostname', {})
    counter = len(hostname_dict)
    all_hostnames = []

    for f in report_files:
        if 'network.txt' in f:
            all_hostnames.extend(HostnameScrubber.extract_hostnames_from_hosts(f))
            all_hostnames.extend(HostnameScrubber.extract_hostnames_from_hostname_section(f))

    all_hostnames.extend(additional_hostnames)
    for h in all_hostnames:
        if h not in hostname_dict:
            hostname_dict[h] = f"hostname_{counter}"
            counter += 1
    return hostname_dict


def extract_usernames(report_files, additional_usernames, mappings):
    username_dict = mappings.get('user', {})
    counter = len(username_dict)
    all_usernames = []

    msg_files = {'messages.txt', 'security-apparmor.txt', 'sssd.txt'}
    for f in report_files:
        base = os.path.basename(f)
        if 'pam.txt' in f:
            sections = ['# /usr/bin/getent passwd', '# /etc/passwd']
            all_usernames.extend(UsernameScrubber.extract_usernames_from_section(f, sections))
        elif base in msg_files:
            all_usernames.extend(UsernameScrubber.extract_usernames_from_messages(f))

    all_usernames.extend(additional_usernames)
    for u in all_usernames:
        if u not in username_dict:
            username_dict[u] = f"user_{counter}"
            counter += 1
    return username_dict


def extract_serials(report_files, mappings):
    scrubber = SerialScrubber(mappings=mappings)
    target_files = {'basic-environment.txt', 'boot.txt', 'hardware.txt'}
    for fpath in report_files:
        if os.path.basename(fpath) in target_files:
            try:
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    scrubber.pre_scan(f.read())
            except Exception:
                pass
    return scrubber.serial_dict


def init_scrubbers(args, config, logger):
    mappings = {}
    mapping_keywords = []
    if args.mappings:
        mappings = load_mappings_file(args.mappings)
        mapping_keywords = list(mappings.get('keyword', {}).keys())

    cmd_keywords = []
    if args.keywords:
        cmd_keywords = [kw.strip() for kw in re.split(r'[,\s;]+', args.keywords.strip()) if kw.strip()]
    combined = set(cmd_keywords).union(mapping_keywords)

    try:
        keyword_scrubber = KeywordScrubber(keyword_file=args.keyword_file, cmd_keywords=list(combined))
        if not keyword_scrubber.is_loaded():
            keyword_scrubber = None
    except Exception as e:
        logger.error(f"Failed to initialize KeywordScrubber: {e}")
        keyword_scrubber = None

    try:
        ip_scrubber = IPScrubber(config, mappings=mappings)
        mac_scrubber = MACScrubber(config, mappings=mappings)
        ipv6_scrubber = IPv6Scrubber(config, mappings=mappings)
    except Exception as e:
        logger.error(f"Error initializing scrubbers: {e}")
        sys.exit(1)

    return mappings, keyword_scrubber, ip_scrubber, mac_scrubber, ipv6_scrubber


def scrub_name(name, hostname_dict):
    for real, fake in sorted(hostname_dict.items(), key=lambda x: len(x[0]), reverse=True):
        name = name.replace(real, fake)
    return name


def dataset_paths(dataset_dir, timestamp, hostname_dict=None, input_name=None, report=False):
    host_tag = ''
    if hostname_dict and input_name:
        for real, fake in sorted(hostname_dict.items(), key=lambda x: len(x[0]), reverse=True):
            short = real.split('.')[0]
            if real in input_name or short in input_name:
                host_tag = f"_{fake}"
                break
    base = f"obfuscation{host_tag}_{timestamp}"
    mapping_path = os.path.join(dataset_dir, f"{base}_mappings.json")
    audit_path   = os.path.join(dataset_dir, f"{base}_audit.json")
    report_path  = os.path.join(dataset_dir, f"{base}_report.json") if report else None
    return mapping_path, audit_path, report_path


def rename_extraction_paths(clean_folder_path, hostname_dict, rename_top=True):
    if not hostname_dict:
        return clean_folder_path
    for root, dirs, _ in os.walk(clean_folder_path, topdown=True):
        for d in dirs:
            scrubbed = scrub_name(d, hostname_dict)
            if scrubbed != d:
                try:
                    os.rename(os.path.join(root, d), os.path.join(root, scrubbed))
                except Exception as e:
                    print(f"[!] Could not rename directory '{d}': {e}", file=sys.stderr)
    if not rename_top:
        return clean_folder_path
    parent   = os.path.dirname(clean_folder_path)
    basename = os.path.basename(clean_folder_path)
    scrubbed_basename = scrub_name(basename, hostname_dict)
    if scrubbed_basename != basename:
        new_path = os.path.join(parent, scrubbed_basename)
        try:
            if os.path.exists(new_path):
                shutil.rmtree(new_path)
            os.rename(clean_folder_path, new_path)
            return new_path
        except Exception as e:
            print(f"[!] Could not rename extraction folder: {e}", file=sys.stderr)
    return clean_folder_path


def is_supportconfig_folder(file_list):
    basenames = {os.path.basename(f) for f in file_list}
    return 'basic-environment.txt' in basenames
