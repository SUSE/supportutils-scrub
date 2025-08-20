# supportutils-scrub

**supportutils-scrub** is a Python-based tool designed to mask sensitive or unwanted information from SUSE supportconfig tarballs and network packet captures. This tool assists users and organizations in aligning with data protection policies, privacy requirements, and GDPR compliance standards.

## Features

- **Comprehensive Data Obfuscation**: Obfuscates sensitive information such as IP addresses (both IPv4 and IPv6), domain names, usernames, hostnames, MAC addresses, and keywords.
- **Subnet-Aware IP Mapping** (v1.1+): Maps whole subnets to fake subnets while preserving host offsets (e.g., gateway .1 remains .1), maintaining meaningful routing and topology for troubleshooting.
- **TcpDump PCAP Obfuscation** (v1.1+): Rewrites packet captures using the same subnet-aware mappings as logs, ensuring consistency across different data types.
- **Consistency Across Runs**: Utilizes obfuscation mappings to ensure consistent data obfuscation across multiple supportconfig files and pcap files.
- **Configurable**: Offers a variety of command-line options and supports a customizable configuration file for tailored scrubbing operations.
- **tcprewrite Integration**: Exports mappings compatible with tcprewrite tool for consistent pcap file obfuscation.

## Installation


### 1. RPM Installation

The supportutils-scrub package is available from the Open Build Service. Choose the appropriate repository for your distribution:

#### openSUSE Leap 15.6 / SLE 15 SP6
```bash
zypper addrepo https://download.opensuse.org/repositories/home:ronald_pina/15.6/home:ronald_pina.repo
zypper refresh
zypper install supportutils-scrub
```

#### openSUSE Leap 15.X / SLE 15 SPX (Generic for any 15.x version)
Replace 15.X with your specific version (e.g., 15.5, 15.4, 15.3):
```bash
zypper addrepo https://download.opensuse.org/repositories/home:ronald_pina/15.X/home:ronald_pina.repo
zypper refresh
zypper install supportutils-scrub
```

#### Direct Downloads and Other Distributions
For direct RPM downloads or other distributions, visit the Open Build Service page:
[https://build.opensuse.org/~ortutils-scrub]


### 2. Install with pip

```bash
git clone https://github.com/SUSE/supportutils-scrub 
cd supportutils-scrub
pip install .
```

### 3. Using the Git folder

```bash
git clone https://github.com/SUSE/supportutils-scrub
cd supportutils-scrub
export PYTHONPATH=$PWD/src:$PYTHONPATH
./bin/supportutils-scrub /var/log/scc_terminus_250814_1549.txz  --verbose
```

## Usage

The supportutils-scrub tool processes a specified supportconfig tarball or directory, creating an obfuscated version. The original data remains untouched unless otherwise specified.

### Basic Supportconfig Obfuscation

```bash
'#' supportutils-scrub /var/log/scc_terminus_250814_1549.txz  \
     --verbose  \
     --domain "corp.local,suse.com"  \
     --hostname "db-prod-01,app-server"  \
     --username "ron,admin"   \
     --keywords "ProjectX,CustomerBeta,SecretDevice"
    
```

**Output:**
```
=============================================================================
          Obfuscation Utility - supportutils-scrub
                      Version : 1.1         
                 Release Date : 2025-08-14  

 supportutils-scrub is a python based tool that masks sensitive
 information from SUSE supportconfig tarballs. It replaces data such as
 IPv4, IPv6, domain names, usernames, hostnames, MAC addresses, and
 custom keywords in a consistent way throughout the archive.
 The mappings are saved in /var/tmp/obfuscation_mappings.json and can be
 reused to keep consistent results across multiple supportconfigs.
=============================================================================

[✓] Loading keywords from file: /tmp/keywords.txt
[✓] Archive extracted to: /var/log/scc_terminus_250814_1549_scrubbed
INFO: Scrubbing:
        basic-environment.txt
        basic-health-check.txt
        boot.txt
        network.txt
        [... additional files ...]

------------------------------------------------------------
 Obfuscation Summary
------------------------------------------------------------
| Files obfuscated          : 72
| Usernames obfuscated      : 1
| IP addresses obfuscated   : 20
| MAC addresses obfuscated  : 86
| Domains obfuscated        : 7
| Hostnames obfuscated      : 2
| IPv6 addresses obfuscated : 44
| Keywords obfuscated       : 2
| Total obfuscation entries : 162
| Size                      : 1.97 MB
| Owner                     : root
| Output archive            : /var/log/scc_terminus_250814_1549_scrubbed.txz
| Mapping file              : /var/tmp/obfuscation_mappings_20250815_125900.json
| Keyword file              : /tmp/keywords.txt
------------------------------------------------------------

 The obfuscated supportconfig has been successfully created. Please review
 its contents to ensure that all sensitive information has been properly
 obfuscated. If some values or keywords were not obfuscated automatically,
 you can manually add them using the keyword obfuscation option.
 =============================================================================


```

### PCAP Obfuscation with tcprewrite (v1.1+)

From version 1.1, `supportutils-scrub` can also rewrite packet captures using the same **subnet-aware** mappings it used for your logs:

#### Features

* **Subnet aware:** Whole IPv4 subnets are mapped to fake subnets (host offsets preserved: e.g., `.1` stays `.1`)
* **Consistent topology:** Routing/masks remain meaningful for troubleshooting
* **Most-specific wins:** Overlapping rules are applied longest-prefix-first
* **Safe by default:** The original pcap is never modified; a new `*_scrubbed.pcap` is written

**Note:** `tcprewrite` does *not* support per-host one-to-one lists; it uses subnet/range rules. The tool exports and uses the `subnet` section from your mapping JSON.

#### Requirements

* Install `tcprewrite` (package: `tcpreplay`)
* Prefer pcaps captured on a **specific interface** (e.g., `-i eth0`), not `-i any`. The `any` device can produce an unsupported link type (DLT) for `tcprewrite`

#### Quick Usage

```bash
# Rewrite one or more pcaps using an existing mapping file
supportutils-scrub \
  --rewrite-pcap \
  --mappings /var/tmp/obfuscation_mappings_20250815_125900.json \
  --pcap-in /var/log/trace.pcap /var/log/trace2.pcap \
  --pcap-out-dir /var/log/ \
  --print-tcprewrite
```

The tool prints a **structured summary** so you can verify translations before/after:

```
=============================================================================

[INFO] Using --rewrite-pcap: original pcaps will remain untouched;
       rewritten copies are saved with suffix _scrubbed.pcap in the chosen output directory.

=== PCAP rewrite mode (IPv4 only) ===
- Input files      : trace.pcap trace2.pcap
- Output directory : /var/log/
- IPv4 rules found : 22

IPv4 subnet rewrite rules (most-specific first):
  192.168.100.0/31  ->  100.112.2.0/31
  88.99.86.0/24     ->  198.18.4.0/24
  3.121.254.0/24    ->  198.18.2.0/24
  192.168.122.0/24  ->  100.112.1.0/24
  192.168.100.0/24  ->  100.112.0.0/24
  188.174.253.0/24  ->  198.18.5.0/24
  16.2.13.0/24      ->  198.18.6.0/24
  148.251.5.0/24    ->  198.18.0.0/24
  144.76.76.0/24    ->  198.18.1.0/24
  129.70.132.0/24   ->  198.18.3.0/24
  10.168.6.0/24     ->  100.80.4.0/24
  ...
[✓] Rewrote pcap file:: /var/log/trace_scrubbed.pcap
```

With `--print-tcprewrite`, you'll also see the **exact command** the wrapper runs (single, consolidated `--srcipmap/--dstipmap` with all rules ordered most-specific first).

### Maintaining Consistency Across Multiple Supportconfigs and HA Clusters

When working with clusters or collecting multiple supportconfigs over time, use the `--mappings` flag to ensure data is replaced consistently:

```bash
# First run on node1, creates a mapping file
supportutils-scrub /var/log/scc_erphana01a_250411_1640.txz

# Second run on node2, or subsequent runs, reuse the same mappings (from node1) for consistency 
supportutils-scrub /var/log/scc_erphana02a_250813_1211.txz \
    --mappings /var/tmp/obfuscation_mappings_20250815_125900.json

# Rewrite associated pcap files using the same mappings
supportutils-scrub \
    --rewrite-pcap \
    --mappings /var/tmp/obfuscation_mappings_20250815_125900.json \
    --pcap-in /var/log/node1.pcap /var/log/node2.pcap \
    --pcap-out-dir /var/log/
```

## Command-Line Options

### Supportconfig Processing Options

- `supportconfig_path`: Path to .txz archive or extracted folder
- `--config PATH`: Path to configuration file (defaults to `/etc/supportutils-scrub/supportutils-scrub.conf`)
- `--verbose`: Enable verbose output
- `--mappings FILE`: JSON file with prior obfuscation mappings for consistency
- `--username USERNAMES`: Additional usernames to obfuscate (comma/semicolon/space-separated)
- `--hostname HOSTNAMES`: Additional hostnames to obfuscate (comma/semicolon/space-separated)
- `--domain DOMAINS`: Additional domains to obfuscate (comma/semicolon/space-separated)
- `--keywords KEYWORDS`: Additional keywords to obfuscate (comma/semicolon/space-separated)
- `--keyword-file FILE`: File containing keywords to obfuscate (one per line)

###  TCPdumps PCAP Processing Options (v1.1+)

- `--rewrite-pcap`: Enable PCAP rewriting mode
- `--pcap-in FILES`: Input PCAP file(s) to obfuscate
- `--pcap-out-dir DIR`: Output directory for obfuscated PCAPs (defaults to current directory)
- `--print-tcprewrite`: Print the exact tcprewrite command being executed

## Configuration File

Default configuration: `/etc/supportutils-scrub/supportutils-scrub.conf`

```ini
obfuscate_private_ip = no     # Set 'yes' to obfuscate private IPs
obfuscate_public_ip = yes
obfuscate_domain = yes
obfuscate_username = yes
obfuscate_hostname = yes
obfuscate_mac = yes
obfuscate_ipv6 = yes
```

**Note:** By default, private IP addresses are NOT obfuscated. To enable private IP obfuscation, set `obfuscate_private_ip = yes`.

## Mapping File Structure

The mapping file (`/var/tmp/obfuscation_mappings_*.json`) contains all translation mappings:

```json

{
    "ip": {
        "10.168.196.180": "100.80.0.180",
        "148.251.5.46": "198.18.0.46",
        "10.149.243.198": "100.80.1.198",
        "192.168.100.128": "100.112.0.128",
        "144.76.76.107": "198.18.1.107",
        "10.100.219.70": "100.80.2.70",
        "10.168.199.254": "100.80.3.254"
    },
    "domain": {
        "corp.local": "domain_0",
        "suse.com": "domain_1",
        "suse.org": "domain_2",
        "new.suse.org": "sub_0.domain_2",
        "lab.new.suse.org": "sub_1.sub_0.domain_2"
    },
    "user": {
        "ron": "user_0",
        "admin": "user_1"
    },
    "hostname": {
        "hammer": "hostname_0",
        "terminus": "hostname_1",
        "db-prod-01": "hostname_2",
        "app-server": "hostname_3"
    },
    "mac": {
        "52:54:00:9a:c4:ad": "00:1A:2B:00:00:00",
        "52:54:00:95:95:72": "00:1A:2B:00:00:01",
        "52:54:00:36:aa:7a": "00:1A:2B:00:00:02",
        "52:54:00:30:29:6e": "00:1A:2B:00:00:03",
        "52:54:00:c5:6a:11": "00:1A:2B:00:00:04",
        "52:54:00:1d:dd:ae": "00:1A:2B:00:00:05",
    },
    "ipv6": {
        "2a07:de40:a102:6::": "2001:db8::",
        "2a07:de40:a102:6:1618:77ff:fe43:a6bb": "2001:db8::1618:77ff:fe43:a6bb",
        "2a07:de40:a102:6:c7b7:c8c9:244:f284": "2001:db8::c7b7:c8c9:244:f284",
        "2a07:de40:a102:6:efc7:b3be:6a28:4ec2": "2001:db8::efc7:b3be:6a28:4ec2",
        "2a07:de40:a102:6:83aa:ccb4:dc8f:1322": "2001:db8::83aa:ccb4:dc8f:1322",
        "2a07:de40:a102:6:1444:4a70:7714:eba0": "2001:db8::1444:4a70:7714:eba0",
    },
    "keyword": {},
    "subnet": {
        "10.168.196.0/24": "100.80.0.0/24",
        "148.251.5.0/24": "198.18.0.0/24",
        "10.149.243.0/24": "100.80.1.0/24",
        "192.168.100.0/24": "100.112.0.0/24",
        "144.76.76.0/24": "198.18.1.0/24",
        "10.100.219.0/24": "100.80.2.0/24",
        "10.168.199.0/24": "100.80.3.0/24",
        "10.149.212.0/24": "100.80.5.0/24",
        "10.100.210.0/24": "100.80.6.0/24",
        "129.70.132.0/24": "198.18.3.0/24",
        "10.145.56.0/24": "100.80.16.0/24",
        "88.99.86.0/24": "198.18.4.0/24",
        "188.174.253.0/24": "198.18.5.0/24",
    },
    "state": {
        "pool_cursor_public": 1792,
        "pool_cursor_priv10": 4352,
        "pool_cursor_priv172": 0,
        "pool_cursor_priv192_168": 514,
        "pool_cursor_linklocal": 0
    },
    "ipv6_subnet": {
        "2a07:de40:a102:6::/64": "2001:db8::/64",
        "2a07:de40:b204:2::/64": "2001:db8:0:1::/64"
    }
}

```

**IMPORTANT:** NEVER share the mapping file with SUSE Support or any third party. This file contains the translation between obfuscated and real data and must remain private.

## Data Sovereignty and Security

- **Customer responsibility:** The obfuscation process is the customer's responsibility. Always review the obfuscated output to ensure all sensitive data is properly masked before sharing.
- **Data sovereignty compliance:** This tool supports SUSE's commitment to digital sovereignty by enabling customers to maintain control over their sensitive data while still receiving technical support.
- **Keyword obfuscation:** Use `--keywords` or `--keyword-file` to remove additional sensitive strings. Keywords are replaced even within words (substring matching).

## License

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2 of the License.

## Author

Ronald Pina <ronald.pina@suse.com>

## See Also

- [supportconfig](https://github.com/openSUSE/supportutils)
- [tcpreplay/tcprewrite](https://tcpreplay.appneta.com/)
