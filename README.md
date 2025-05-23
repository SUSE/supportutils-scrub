# supportutils-scrub

**supportutils-scrub** is a Python-based tool designed to mask sensitive or unwanted information from SUSE supportconfig tarballs. This tool assists users and organizations in aligning with data protection policies, privacy requirements, and GDPR compliance standards.

## Features
- **Comprehensive Data Obfuscation**: Obfuscates sensitive information such as IP addresses (both IPv4 and IPv6), domain names, usernames, hostnames, MAC addresses, and keywords.
- **Consistency Across Runs**: Utilizes obfuscation mappings to ensure consistent data obfuscation across multiple supportconfig files.
- **Configurable**: Offers a variety of command-line options and supports a customizable configuration file for tailored scrubbing operations.

## Installation

### 1. RPM Installation
To install and set up the `supportutils-scrub` tool for testing and development, you can find the rpms here:
 [https://build.opensuse.org/package/show/home:ronald_pina/supportutils-scrub]

### 2. Install with pip
    git clone  git clone https://github.com/SUSE/supportutils-scrub 
    cd supportutils-scrub
    pip install .

### 3. Using the Git folder
     git clone https://github.com/SUSE/supportutils-scrub
     cd supportutils-scrub
     export PYTHONPATH=$PWD/src:$PYTHONPATH
     ./bin/supportutils-scrub /var/log/scc_zitrone_250416_1330.txz  --verbose
     
## Usage

The supportutils-scrub tool processes a specified supportconfig tarball or directory, creating an obfuscated version. The original data remains untouched unless otherwise specified.

```bash
 supportutils-scrub /var/log/scc_zitrone_250416_1330.txz     --verbose \
                                                              --username ron,alex \
                                                              --hostname zitrone,terminus
                                                              --domain suse.de,example.com 
                                                              --keywords linux,ronald

=============================================================================
          Obfuscation Utility - supportutils-scrub
               Script Version : 1.0.0       
                 Release Date : 2025-04-18  

 supportutils-scrub is a python based tool that masks sensitive
 information from SUSE supportconfig tarballs. It replaces data such as
 IPv4, IPv6, domain names, usernames, hostnames, MAC addresses, and
 custom keywords in a consistent way throughout the archive.
 The mappings are saved in /var/tmp/obfuscation_mappings.json and can be
 reused to keep consistent results across multiple supportconfigs.
=============================================================================

[!] Configuration file not found: /etc/supportutils-scrub/supportutils-scrub.conf
    → Using built-in default settings.
[✓] Archive extracted to: /var/log/scc_zitrone_250416_1330_scrubbed
INFO: Scrubbing:
    basic-environment.txt
    basic-health-check.txt
    boot.txt
    bpf.txt
    cimom.txt
    crash.txt
    sa20250416 [binary] (skipped)
    ...
[✓] Scrubbed archive written to: /var/log/scc_zitrone_250416_1330_scrubbed.txz
[✓] Mapping file saved to:       /var/tmp/obfuscation_mappings.json

--- Obfuscated Mapping Preview ---
{
    "ip": {
        "10.203.195.4": "42.42.1.2",
        "10.203.192.91": "42.42.2.3",
        "10.203.192.94": "42.42.3.4",
        "0.0.0.0": "42.42.4.5",
        "169.254.169.254": "42.42.5.6",
        "127.0.0.1": "42.42.6.7",
  },
    "domain": {
        "sap.local": "domain_0",
        "google.local": "domain_1",
        "customer.com": "domain_2",
        "abc-org-sap.local": "domain_3",
        "tec-prj-sap.local": "domain_4",
        "suse.de": "domain_5",
        "example.com": "domain_6",
    },
    "user": {
        "ron": "user_0",
        "alex": "user_1",
        "nobody": "user_2",
        "root": "user_3",
        "a3padm": "user_4",
        "i3padm": "user_5",
        "admin_tec": "user_6",
    },
    "hostname": {
        "metadata": "hostname_0",
        "tec1128": "hostname_1",
        "albew7": "hostname_2",
        "ARPD3": "hostname_3",
        "TNSV3": "hostname_4",
        "smt-gce": "hostname_15",
        "zitrone": "hostname_16",
        "terminus": "hostname_17",
    ...
    },
    "mac": {
        "04:7b:cb:68:bc:e5": "00:1A:2B:01:02:03",
        "88:a4:c2:d6:1a:9c": "00:1A:2B:02:03:04",
        "02:42:e3:e7:9b:8e": "00:1A:2B:03:04:05",
        "00:00:00:00:00:00": "00:00:00:00:00:00",
        "38:d5:7a:44:42:bf": "00:1A:2B:04:05:06",
        "02:42:08:c6:18:c3": "00:1A:2B:05:06:07",
        "cc:d3:c1:f6:5e:bf": "00:1A:2B:06:07:08",
        "00:09:0f:09:00:1e": "00:1A:2B:07:08:09",
        "33:33:00:00:00:01": "00:1A:2B:08:09:0A",
        "52:54:00:1a:97:48": "00:1A:2B:12:13:14"
    },
    "ipv6": {
        "2a01:4f8:1c0c:44b8::2": "2001:0db8:85a3::0:1:2",
        "2a05:d014:fc5:9a00:38e:25ed:3c41:88ec": "2001:0db8:85a3::1:2:3",
        "fe80::19fa:6a99:15db:bc09": "2001:0db8:85a3::2:3:4",
        "2001:9e8:3d3f:9b00:847c:ba7c:cc93:39c": "2001:0db8:85a3::3:4:5",
        "fd00::7642:7fff:fe91:5a8": "2001:0db8:85a3::4:5:6",
        "2001:9e8:3d3f:9b00:7642:7fff:fe91:5a8": "2001:0db8:85a3::5:6:7",
        "2001:9e8:3d3f:9b00:8c9:68a1:9949:c6cc": "2001:0db8:85a3::6:7:8",
        "fd00::2dfa:bef0:de32:689b": "2001:0db8:85a3::7:8:9",
        "fd00::f6ad:1c64:4a39:2a6b": "2001:0db8:85a3::8:9:a",
        "2001:9e8:3d08:1d00:5d0c:7ec3:2a98:d6f4": "2001:0db8:85a3::9:a:b",
        "2a00:1450:4001:0829:0000:0000:0000:200e": "2001:0db8:85a3::45:46:47",
        "2001:4860:4860:0000:0000:0000:0000:8844": "2001:0db8:85a3::46:47:48",
        "2a00:1450:4001:082b:0000:0000:0000:200a": "2001:0db8:85a3::47:48:49"
    },
    "keyword": {
        "applicationx": "xxxxxxx",
        "google": "xxxxxxxx"
    },
}

------------------------------------------------------------
 Obfuscation Summary
------------------------------------------------------------
| Files obfuscated          : 90
| Usernames obfuscated      : 5
| IP addresses obfuscated   : 161
| MAC addresses obfuscated  : 20
| Domains obfuscated        : 23
| Hostnames obfuscated      : 27
| IPv6 addresses obfuscated : 57
| Keywords obfuscated       : 2
| Total obfuscation entries : 295
| Size                      : 3.93 MB
| Owner                     : root
| Output archive            : /var/log/scc_zitrone_250416_1330_scrubbed.txz
| Mapping file              : /var/tmp/obfuscation_mappings.json
------------------------------------------------------------

 The obfuscated supportconfig has been successfully created. Please review
 its contents to ensure that all sensitive information has been properly
 obfuscated. If some values or keywords were not obfuscated automatically,
 you can manually add them using the keyword obfuscation option.
=============================================================================

```
