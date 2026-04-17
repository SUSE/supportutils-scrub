# supportutils-scrub

**supportutils-scrub** is a Python-based tool designed to mask sensitive or unwanted information from SUSE supportconfig tarballs and network packet captures. This tool assists users and organizations in aligning with data protection policies, privacy requirements, and GDPR compliance standards.

## Features

- **Comprehensive Data Obfuscation**: Obfuscates IPv4/IPv6 addresses, MAC addresses, domain names, hostnames, usernames, hardware serial numbers, system UUIDs, and custom keywords — consistently across every file in the archive.
- **Subnet-Aware IP Mapping**: Maps whole subnets to fake subnets while preserving host offsets (e.g., gateway `.1` remains `.1`), maintaining meaningful routing and topology for troubleshooting.
- **LDAP / SSSD DN Obfuscation** (v1.2+): Obfuscates LDAP distinguished names in `DC=` format (e.g. `DC=example,DC=com`) found in SSSD configurations. Fake domains preserve the DC= component count so the structure remains readable for support analysis.
- **Hardware Serial Number / UUID Obfuscation** (v1.3+): Detects and replaces hardware serial numbers and system UUIDs from `dmidecode` output (`Serial Number:`, `UUID:`, `Asset Tag:`). Placeholder values like `Not Specified` are not touched.
- **Email Address Obfuscation** (v1.3+): Detects and replaces email addresses consistently across all files. Systemd template units (e.g., `user@1000.service`) and vendor/upstream addresses (kernel.org, suse.com, etc.) are preserved.
- **Password Value Obfuscation** (v1.3+): Replaces password values in configuration lines (e.g., `password=secret123`) while preserving the key prefix. Values already redacted by supportconfig (`*REMOVED BY SUPPORTCONFIG*`) are skipped.
- **Cloud Token / Credential Obfuscation** (v1.4+): Detects and replaces AWS access keys (AKIA/ASIA), AWS secret keys, Azure connection strings and SAS tokens, GCP private keys, JWTs, and bearer tokens.
- **Flexible Input Modes** (v1.2+): Accepts `.txz`/`.tgz` supportconfigs, `crm_report`/`hb_report` `.tar.gz` archives, plain directories, single files, and stdin — making it easy to obfuscate the output of commands like `journalctl` directly in a pipeline.
- **Multi-Archive / Cluster Support** (v1.2+): Process multiple supportconfigs in one run with shared mappings, keeping values consistent across all HA cluster nodes.
- **PCAP Obfuscation**: Rewrites tcpdump captures using the same subnet-aware IP mappings via `tcprewrite`, ensuring logs and packet captures tell a consistent story.
- **Consistency Across Runs**: Mapping files (plain or encrypted) can be saved and reloaded to guarantee the same fake values are reused across different runs or supportconfigs.
- **Multi-Layer Post-Scrub Verification** (v1.3+): `--verify` performs a deep scan of the scrubbed output using five verification layers: (1) mapping-based checks, (2) IPv4 allowlist — flags any IP not in the fake pools, (3) MAC allowlist — flags any MAC not using the fake OUI, (4) pattern scan — detects emails, private keys, API tokens, JWTs, passwords, LDAP DNs, and Kerberos principals independent of the mapping, (5) identity extraction (folder mode) — parses the original supportconfig for hostname, IPs, MACs, DNS servers, and serials, then verifies none survive in the scrubbed output. Exits with code 3 if leaks are found.
- **Coverage & Verification Report** (v1.3+): `--report` writes a JSON file listing which files contained each data category and, when combined with `--verify`, includes the full list of verification findings — useful for compliance evidence and auditing.

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
git clone https://github.com/openSUSE/supportutils-scrub
cd supportutils-scrub
pip install .
```

### 3. Using the Git folder

```bash
git clone https://github.com/openSUSE/supportutils-scrub
cd supportutils-scrub
export PYTHONPATH=$PWD/src:$PYTHONPATH
./bin/supportutils-scrub /var/log/scc_terminus_250814_1549.txz --verbose
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
                      Version : 1.4
                 Release Date : 2026-04-01

 supportutils-scrub masks sensitive information from SUSE supportconfig
 tarballs, directories, plain files, and network captures. It replaces
 IPv4/IPv6 addresses, MAC addresses, domain names, hostnames, usernames,
 hardware serials, UUIDs, email addresses, passwords, and cloud tokens
 (AWS/Azure/GCE) consistently across all files in the archive.
 Mappings are saved to /var/tmp/obfuscation_HOSTNAME_TIMESTAMP_mappings.json
 (or .json.enc with --encrypt-mappings) and can be reused across runs
 with --mappings to keep values consistent across multiple archives.
=============================================================================

[✓] Archive extracted to: /var/log/scc_hostname_1_250814_1549_scrubbed
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
| Serials/UUIDs obfuscated  : 3
| Emails obfuscated         : 2
| Passwords obfuscated      : 1
| Cloud tokens obfuscated   : 0
| Keywords obfuscated       : 2
| Total obfuscation entries : 180
| Size                      : 1.97 MB
| Owner                     : root
| Output archive            : /var/log/scc_hostname_1_250814_1549_scrubbed.txz
| Mapping file              : /var/tmp/obfuscation_mappings_20250815_125900.json
| Audit log                 : /var/tmp/obfuscation_audit_20250815_125900.json
------------------------------------------------------------
```

> Note: The output archive filename has the real hostname replaced (e.g. `scc_terminus_...` → `scc_hostname_1_...`).

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

### Streaming Mode — Live Pipes (v1.3+)

By default, stdin mode reads all input before producing any output (batch mode). This is correct for files but **blocks indefinitely** on a live source like `journalctl -f`.

Use `--stream` to scrub and flush each line immediately after an initial 500-line bootstrap window that builds the entity maps:

```bash
# Live journal — scrub and flush each line in real time
journalctl -f | supportutils-scrub --stream --no-mappings

# Live pacemaker journal with explicit entities
journalctl -f -u pacemaker \
  | supportutils-scrub --stream \
      --hostname node1,node2 \
      --domain corp.example.com \
      --mappings /var/tmp/obfuscation_mappings.json

# Feed scrubbed live logs directly to a local AI agent
journalctl -f \
  | supportutils-scrub --stream --no-mappings \
  | ai-agent --listen-stdin
```

> **Note:** Entities that first appear after the 500-line bootstrap window may not be detected automatically. Declare known hostnames, domains, and usernames explicitly with `--hostname`, `--domain`, `--username` when using `--stream`.

### Single File Mode (v1.2+)

Scrub a single plain-text file. A `_scrubbed` copy is written next to the original:

```bash
supportutils-scrub /var/log/messages
# Output: /var/log/messages_scrubbed
```

Each real TLD (`.com`, `.net`, `.de`, ...) is mapped to a unique 3-letter sequence (`aaa`, `aab`, `aac`, ...) that is consistent across runs when reusing a mapping file.

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
- `--report FILE`: Write a JSON report to FILE. Includes coverage data and, with `--verify`, the full list of verification findings.
- `--verify`: Multi-layer post-scrub verification: mapping checks, IP/MAC allowlists, pattern scan (emails, secrets, keys), and identity extraction. Exits with code 3 if leaks found.
- `--stream`: Streaming stdin mode. Buffers the first 500 lines to build entity maps, then scrubs and flushes each subsequent line immediately. Required for live pipes such as `journalctl -f`. Without this flag, stdin mode waits for EOF before producing any output.

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
# Obfuscation controls
obfuscate_private_ip = yes    # Set 'no' to leave private IPs (10.x, 172.16.x, 192.168.x, ULA, link-local) untouched
obfuscate_public_ip = yes
obfuscate_domain = yes
obfuscate_username = yes
obfuscate_hostname = yes
obfuscate_mac = yes
obfuscate_ipv6 = yes
obfuscate_serial = yes

# Security controls
secure_tmp = no               # Set 'yes' to extract to /dev/shm (RAM only)
encrypt_mappings = no         # Set 'yes' to encrypt the mapping file with a passphrase
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
        "corp.example.com": "domain_0.aaa",
        "sub.corp.example.com": "sub_0.domain_0.aaa",
        "suse.net": "domain_1.aab"
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
    "serial": {
        "ABC123XYZ456": "SERIAL_0",
        "12345678-abcd-ef12-3456-789012345678": "00000000-0000-0000-0000-000000000001"
    },
    "keyword": {},
    "email": {
        "admin@company.com": "email_1@scrubbed.local",
        "user@corp.example.com": "email_2@scrubbed.local"
    },
    "password": {
        "ce99185f0ff046d3": "scrubbed_pass_1"
    },
    "cloud_token": {
        "AKIA...EXAMPLE": "SCRUBBED_AWS_KEY_1"
    },
    "subnet": {
        "10.168.196.0/24": "100.80.0.0/24",
        "148.251.5.0/24": "198.18.0.0/24",
        "192.168.100.0/24": "100.112.0.0/24"
    },
    "tld_map": {
        "com": "aaa",
        "net": "aab",
        "de":  "aac"
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
    "version":      "1.4",
    "timestamp":    "2026-04-04T14:22:01Z",
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

For use in sensitive environments, the following optional security controls are available:

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

Settable in config: `encrypt_mappings = yes`

### RAM-Only Temporary Extraction

By default, archives are extracted to disk. Use `--secure-tmp` to extract to `/dev/shm` (tmpfs) so sensitive data stays in RAM only and is guaranteed cleaned up:

```bash
supportutils-scrub /var/log/scc_node1.txz --secure-tmp
```

Settable in config: `secure_tmp = yes`

### No Mapping File

When a one-shot scrub is sufficient and no mapping file should exist on disk:

```bash
supportutils-scrub /var/log/scc_node1.txz --no-mappings
```

### Post-Scrub Verification (v1.3+)

After scrubbing, `--verify` performs a multi-layer scan of the output to detect remaining sensitive data:

1. **Mapping-based** — checks that all known real values were replaced
2. **IPv4 allowlist** — every IP in the output must be in a known-safe range (fake pools, loopback, multicast, documentation nets). Private IPs are safe when `obfuscate_private_ip = no`.
3. **MAC allowlist** — every MAC must use the fake OUI prefix (`00:1A:2B`). Broadcast (`ff:ff:ff:ff:ff:ff`) and null MACs are safe.
4. **Pattern scan** — detects emails, private keys, certificates, API tokens, JWTs, passwords, LDAP DNs, and Kerberos principals — independent of the mapping.
5. **Identity extraction** (folder mode) — parses `basic-environment.txt`, `network.txt`, and `hardware.txt` from the original to extract hostname, IPs, MACs, DNS servers, serial numbers, and UUIDs, then verifies none survive in the scrubbed output.

```bash
supportutils-scrub /var/log/scc_node1.txz --verify
# [✓] VERIFY: No sensitive data found in scrubbed output.
```

If leaks are found, the tool reports the exact file, line number, category, and value. Use `--report` to save the full findings list.

### Coverage & Verification Report (v1.3+)

Write a JSON report including coverage data and (with `--verify`) the full list of verification findings:

```bash
supportutils-scrub /var/log/scc_node1.txz \
    --verify --report /var/tmp/scrub_report_$(date +%Y%m%d).json
```

## Disclaimer

supportutils-scrub is a best-effort obfuscation tool. It does not guarantee that all sensitive data has been removed from the output. The operator is responsible for reviewing the scrubbed output before sharing it with any third party. Use `--verify` to perform an automated post-scrub scan, but note that automated verification cannot detect all forms of sensitive data. SUSE accepts no liability for data disclosed in scrubbed archives.

## License

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2 of the License.

## Author

Ronald Pina <ronald.pina@suse.com>

## See Also

- [supportconfig](https://github.com/openSUSE/supportutils)
- [tcpreplay/tcprewrite](https://tcpreplay.appneta.com/)
