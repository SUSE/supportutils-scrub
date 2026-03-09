# supportutils-scrub

**supportutils-scrub** is a Python-based tool designed to mask sensitive or unwanted information from SUSE supportconfig tarballs and network packet captures. This tool assists users and organizations in aligning with data protection policies, privacy requirements, and GDPR compliance standards.

## Features

- **Comprehensive Data Obfuscation**: Obfuscates IPv4/IPv6 addresses, MAC addresses, domain names, hostnames, usernames, and custom keywords — consistently across every file in the archive.
- **Subnet-Aware IP Mapping**: Maps whole subnets to fake subnets while preserving host offsets (e.g., gateway `.1` remains `.1`), maintaining meaningful routing and topology for troubleshooting.
- **LDAP / SSSD DN Obfuscation** (v1.2+): Obfuscates LDAP distinguished names in `DC=` format (e.g. `DC=example,DC=com`) found in SSSD configurations. Fake domains preserve the DC= component count so the structure remains readable for support analysis.
- **Flexible Input Modes** (v1.2+): Accepts `.txz`/`.tgz` supportconfigs, `crm_report`/`hb_report` `.tar.gz` archives, plain directories, single files, and stdin — making it easy to obfuscate the output of commands like `journalctl` directly in a pipeline.
- **Multi-Archive / Cluster Support** (v1.2+): Process multiple supportconfigs in one run with shared mappings, keeping values consistent across all HA cluster nodes.
- **PCAP Obfuscation**: Rewrites tcpdump captures using the same subnet-aware IP mappings via `tcprewrite`, ensuring logs and packet captures tell a consistent story.
- **Consistency Across Runs**: Mapping files can be saved and reloaded to guarantee the same fake values are reused across different runs or supportconfigs.

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
[https://software.opensuse.org//download.html?project=home%3Aronald_pina&package=supportutils-scrub]


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

### Basic Supportconfig Obfuscation

```bash
supportutils-scrub /var/log/scc_terminus_250814_1549.txz \
     --verbose  \
     --domain "corp.example.com"  \
     --hostname "db-prod-01,app-server"  \
     --username "ron,admin"   \
     --keywords "ProjectX,CustomerBeta,SecretDevice"
```

**Output:**
```
=============================================================================
          Obfuscation Utility - supportutils-scrub
                      Version : 1.2         
                 Release Date : 2026-02-24  

 supportutils-scrub is a python based tool that masks sensitive
 information from SUSE supportconfig tarballs. It replaces data such as
 IPv4, IPv6, domain names, usernames, hostnames, MAC addresses, and
 custom keywords in a consistent way throughout the archive.
 The mappings are saved in /var/tmp/obfuscation_mappings.json and can be
 reused to keep consistent results across multiple supportconfigs.
=============================================================================

[!] Configuration file not found: /etc/supportutils-scrub/supportutils-scrub.conf.
     → Using default settings
[!] WARNING: Private IP obfuscation is DISABLED.
    Only public IP addresses will be obfuscated.
    To also obfuscate private IPs (10.x, 172.16.x, 192.168.x),
    set 'obfuscate_private_ip = yes' in /etc/supportutils-scrub/supportutils-scrub.conf

[✓] Archive extracted to: /var/log/scc_terminus_250814_1549_scrubbed
        basic-environment.txt
        basic-health-check.txt
        boot.txt
        network.txt
        sssd.txt
        [... additional files ...]

------------------------------------------------------------
 Obfuscation Summary
------------------------------------------------------------
| Files obfuscated          : 72
| Usernames obfuscated      : 1
| IP addresses obfuscated   : 20
| IPv4 subnets obfuscated   : 8
| MAC addresses obfuscated  : 86
| Domains obfuscated        : 7
| Hostnames obfuscated      : 2
| IPv6 addresses obfuscated : 44
| IPv6 subnets obfuscated   : 2
| Keywords obfuscated       : 2
| Total obfuscation entries : 172
| Size                      : 1.97 MB
| Owner                     : root
| Output archive            : /var/log/scc_terminus_250814_1549_scrubbed.txz
| Mapping file              : /var/tmp/obfuscation_mappings_20250815_125900.json
------------------------------------------------------------
```

### Multi-Archive Mode — HA Clusters (v1.2+)

Pass all cluster archives in a single run — both node supportconfigs and the `crm_report`/`hb_report` `.tar.gz`. Mappings are chained so the same real value always maps to the same fake value across all archives:

```bash
supportutils-scrub scc_hana-t1_260222_2336.txz scc_hana-t2_260222_2337.txz crm_report-Mon-23-Feb-2026.tar.gz
```

Or reuse mappings from a previous run for consistency:

```bash
# Node 1 — creates the mapping file
supportutils-scrub scc_hana-t1_260222_2336.txz

# Node 2 + crm_report — reuse node 1 mappings
supportutils-scrub scc_hana-t2_260222_2337.txz crm_report-Mon-23-Feb-2026.tar.gz \
    --mappings /var/tmp/obfuscation_mappings_20260222_125900.json
```

### Stdin / Pipeline Mode (v1.2+)

Pipe any text through the scrubber using an existing mapping file. Useful for obfuscating live command output before sharing:

```bash
journalctl -u pacemaker --since "1 hour ago" \
  | supportutils-scrub - --mappings /var/tmp/obfuscation_mappings.json \
  > pacemaker_scrubbed.log
```

### Single File Mode (v1.2+)

Scrub a single plain-text file. A `_scrubbed` copy is written next to the original:

```bash
supportutils-scrub /var/log/messages
# Output: /var/log/messages_scrubbed
```

### SSSD / Active Directory Obfuscation (v1.2+)

`sssd.txt` is pre-scanned for domain names. Both dot-notation and LDAP DN (`DC=`) formats are replaced, with the component structure preserved:

**Original:**
```
domains = corp.example.com
ldap_search_base      = DC=corp,DC=example,DC=com
ad_access_filter      = (&(memberOf=CN=SupportGroup,OU=Groups,DC=corp,DC=example,DC=com))
krb5_realm            = CORP.EXAMPLE.COM
```

**Scrubbed:**
```
domains = domain_0.obf
ldap_search_base      = DC=domain_0,DC=obf
ad_access_filter      = (&(memberOf=CN=SupportGroup,OU=Groups,DC=domain_0,DC=obf))
krb5_realm            = domain_0.obf
```

### PCAP Obfuscation with tcprewrite

Rewrite packet captures using the same subnet-aware mappings used for the logs:

```bash
supportutils-scrub \
  --rewrite-pcap \
  --mappings /var/tmp/obfuscation_mappings_20250815_125900.json \
  --pcap-in /var/log/trace.pcap /var/log/trace2.pcap \
  --pcap-out-dir /var/log/ \
  --print-tcprewrite
```

```
=== PCAP rewrite mode (IPv4 only) ===
- Input files      : trace.pcap trace2.pcap
- Output directory : /var/log/
- IPv4 rules found : 22

IPv4 subnet rewrite rules (most-specific first):
  192.168.100.0/31  ->  100.112.2.0/31
  88.99.86.0/24     ->  198.18.4.0/24
  192.168.122.0/24  ->  100.112.1.0/24
  192.168.100.0/24  ->  100.112.0.0/24
  10.168.6.0/24     ->  100.80.4.0/24
  ...
[✓] Rewrote pcap file: /var/log/trace_scrubbed.pcap
```

**Requirements:** Install `tcprewrite` (package: `tcpreplay`). Prefer pcaps captured on a specific interface (e.g., `-i eth0`), not `-i any`.

## Command-Line Options

### Supportconfig Processing

- `supportconfig_path`: Path(s) to `.txz`/`.tgz` archive(s), a folder, a plain file, or `-` for stdin. Multiple archives share mappings.
- `--config PATH`: Path to configuration file (default: `/etc/supportutils-scrub/supportutils-scrub.conf`)
- `--verbose`: Enable verbose output
- `--quiet`: Suppress the startup banner and per-file listing. Errors and warnings still go to stderr. Useful when called from scripts or `supportconfig`.
- `--mappings FILE`: JSON or encrypted `*.json.enc` mapping file from a prior run. Prompts for passphrase automatically when the file is encrypted.
- `--username USERNAMES`: Additional usernames to obfuscate (comma/semicolon/space-separated)
- `--hostname HOSTNAMES`: Additional hostnames to obfuscate
- `--domain DOMAINS`: Additional domains to obfuscate
- `--keywords KEYWORDS`: Additional keywords to obfuscate
- `--keyword-file FILE`: File containing keywords to obfuscate (one per line)
- `--output-dir DIR`: Write the scrubbed archive to DIR instead of alongside the input file.
- `--report FILE`: Write a JSON coverage report to FILE listing which files contained each data category (IPv4, domain, hostname, serial, etc.).
- `--verify`: After scrubbing, re-scan the output for any remaining real values. Exits with code 3 if leaks are found; exits 0 if clean.

### PCAP Processing

- `--rewrite-pcap`: Enable PCAP rewriting mode
- `--pcap-in FILES`: Input PCAP file(s) to obfuscate
- `--pcap-out-dir DIR`: Output directory for obfuscated PCAPs (default: current directory)
- `--print-tcprewrite`: Print the exact tcprewrite command being executed
- `--tcprewrite-path PATH`: Path to the tcprewrite binary (default: `tcprewrite`)

### Security Options

- `--secure-tmp`: Extract archives to `/dev/shm` (RAM-backed tmpfs) so sensitive data never touches persistent storage. Falls back to `/var/tmp` with a warning if unavailable. Cleanup is guaranteed even on interruption.
- `--encrypt-mappings`: Encrypt the mapping file with a passphrase (AES-128/Fernet). The file is saved as `*.json.enc`. Requires `pip install cryptography`. Also settable via `encrypt_mappings = yes` in the config file.
- `--no-mappings`: Do not write a mapping file. Use for one-shot obfuscation where the mapping file itself is a risk.
- `--decrypt-mappings FILE`: Decrypt and print an encrypted mapping file (`*.json.enc`) to stdout, then exit. Passing a `*.json.enc` file as a positional argument triggers decrypt mode automatically.

## Configuration File

Default: `/etc/supportutils-scrub/supportutils-scrub.conf`

```ini
obfuscate_private_ip = no     # Set 'yes' to obfuscate private IPs
obfuscate_public_ip = yes
obfuscate_domain = yes
obfuscate_username = yes
obfuscate_hostname = yes
obfuscate_mac = yes
obfuscate_ipv6 = yes
```

**Note:** Private IP addresses are not obfuscated by default.

## Mapping File Structure

The mapping file (`/var/tmp/obfuscation_mappings_*.json`) records every translation made during a run:

```json
{
    "ip": {
        "10.168.196.180": "100.80.0.180",
        "148.251.5.46": "198.18.0.46",
        "192.168.100.128": "100.112.0.128"
    },
    "domain": {
        "corp.example.com": "domain_0.obf",
        "sub.corp.example.com": "sub_0.domain_0.obf"
    },
    "user": {
        "ron": "user_0",
        "admin": "user_1"
    },
    "hostname": {
        "db-prod-01": "hostname_0",
        "app-server": "hostname_1"
    },
    "mac": {
        "52:54:00:9a:c4:ad": "00:1A:2B:00:00:00",
        "52:54:00:95:95:72": "00:1A:2B:00:00:01"
    },
    "ipv6": {
        "2a07:de40:a102:6::": "2001:db8::",
        "2a07:de40:a102:6:1618:77ff:fe43:a6bb": "2001:db8::1618:77ff:fe43:a6bb"
    },
    "keyword": {},
    "subnet": {
        "10.168.196.0/24": "100.80.0.0/24",
        "148.251.5.0/24": "198.18.0.0/24",
        "192.168.100.0/24": "100.112.0.0/24"
    },
    "state": {
        "pool_cursor_public": 1792,
        "pool_cursor_priv10": 4352,
        "pool_cursor_priv172": 0,
        "pool_cursor_priv192_168": 514,
        "pool_cursor_linklocal": 0
    },
    "ipv6_subnet": {
        "2a07:de40:a102:6::/64": "2001:db8::/64"
    }
}
```

**IMPORTANT:** Never share the mapping file with SUSE Support or any third party. It contains the translation between real and obfuscated data and must remain private.

## Audit Trail

After every run, an audit log is written to `/var/tmp/obfuscation_audit_TIMESTAMP.json` (mode 0600). It records:

```json
{
    "tool":         "supportutils-scrub",
    "version":      "1.2",
    "timestamp":    "2026-03-09T14:22:01Z",
    "operator":     "root",
    "hostname":     "myserver",
    "mode":         "archive",
    "inputs":  [{"path": "/var/log/scc_node1.txz",          "sha256": "e3b0c4..."}],
    "outputs": [{"path": "/var/log/scc_node1_scrubbed.txz", "sha256": "a665a4..."}],
    "cli_args":     ["--domain", "corp.example.com"],
    "mapping_file": "/var/tmp/obfuscation_mappings_20260309_142201.json"
}
```

This provides chain of custody: proof of who ran the tool, on which files, producing which output. Keep the audit log alongside the scrubbed archive before sharing with support.

## Data Sovereignty and Security

- **Customer responsibility:** Always review the obfuscated output before sharing to confirm all sensitive data is properly masked.
- **Data sovereignty compliance:** This tool supports SUSE's commitment to digital sovereignty by letting customers control their sensitive data while still receiving technical support.
- **Keyword obfuscation:** Use `--keywords` or `--keyword-file` to remove additional sensitive strings not caught automatically.

## Security Hardening

For use in sensitive environments, four optional security controls are available:

### Encrypted Mapping File

The mapping file maps every real value to its fake replacement — if leaked alongside the scrubbed archive, it fully reverses the obfuscation. Protect it:

```bash
supportutils-scrub /var/log/scc_node1.txz --encrypt-mappings
# Prompts for passphrase → writes obfuscation_mappings_*.json.enc
```

To reuse an encrypted mapping file for scrubbing another archive, pass it directly to `--mappings`. The tool detects the `.enc` extension and prompts for the passphrase:

```bash
supportutils-scrub /var/log/scc_node2.txz \
    --mappings /var/tmp/obfuscation_mappings_20260309_142201.json.enc
# Passphrase for ...: (prompted)
```

To inspect the encrypted file later, simply pass it to the tool:

```bash
supportutils-scrub /var/tmp/obfuscation_mappings_20260309_142201.json.enc
# or explicitly:
supportutils-scrub --decrypt-mappings /var/tmp/obfuscation_mappings_20260309_142201.json.enc
Passphrase for ...:
{ ... JSON output ... }
```

### RAM-Only Temporary Extraction

By default, archives are extracted to disk. Use `--secure-tmp` to extract to `/dev/shm` (tmpfs) so sensitive data stays in RAM only and is guaranteed cleaned up:

```bash
supportutils-scrub /var/log/scc_node1.txz --secure-tmp
```

### No Mapping File

When a one-shot scrub is sufficient and no mapping file should exist on disk:

```bash
supportutils-scrub /var/log/scc_node1.txz --no-mappings
```

These options are also available in the configuration file:

```ini
secure_tmp = yes
encrypt_mappings = yes
```

## supportconfig Integration

`supportutils-scrub` is designed to be called directly from the `supportconfig` script. Set defaults via the environment variable so `supportconfig` can pass options without changing the call interface:

```bash
export SUPPORTUTILS_SCRUB_OPTS="--quiet --output-dir /var/log/scrubbed"
supportutils-scrub /var/log/scc_node1.txz
```

Exit codes for programmatic use:
| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Fatal error |
| 2 | Completed with warnings |
| 3 | `--verify` found remaining sensitive data |

## License

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2 of the License.

## Author

Ronald Pina <ronald.pina@suse.com>

## See Also

- [supportconfig](https://github.com/openSUSE/supportutils)
- [tcpreplay/tcprewrite](https://tcpreplay.appneta.com/)
