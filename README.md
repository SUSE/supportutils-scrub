# supportutils-scrub

Supportutils-scrub is a python-based application dedicated to sanitizing and eliminating sensitive or unwanted data from SUSE supportconfig tarballs. This tool helps users and organizations to align with organizational data protection policies, privacy requirements and GDPR compliance standards.

## Usage:

```sh
git clone https://github.com/pinaronald/supportutils-scrub.git
cd supportutils-scrub/bin
./supportutils-scrub /var/log/scc_supportconfig_240419_0503.txz --verbose --username ron,alex --hostname zitrone,terminus --domain suse.de,example.com

INFO: Keyword file is missing or empty. Skipping keyword scrubbing.
INFO: Extracted .txz to: /var/log/scc_supportconfig_240419_0503_scrubbed
INFO: Extraction completed. Clean folder path: /var/log/scc_supportconfig_240419_0503_scrubbed
INFO: Scrubbing:
    basic-environment.txt
    basic-health-check.txt
    boot.txt
    bpf.txt
    cimom.txt
    crash.txt
    ...
    ...
INFO: New scrubbed TXZ file created at: /var/log/scc_supportconfig_240419_0503_scrubbed.txz
INFO: Obfuscation datasets mappings saved at: /usr/lib/supportconfig/obfuscation_dataset_mappings.json
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
 "keyword": {},
}
