# supportutils-scrub	
Supportutils-scrub is a python-based application dedicated to sanitizing and eleminataing sensitive or unwanted data from SUSE supportconfig tarballs. This tool helps users and organizations to align with organizational data protection policies, privacy requirements and GPDR compliance standards.

Usage:

git clone https://github.com/pinaronald/supportutils-scrub.git
# cd supportutils-scrub/bin
# ./supportutils-scrub /var/log/scc_supportconfig_240419_0503.txz --verbose --username ron,alex --hostname zitrone,terminus --domain suse.de,example.com
 
 
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
Obfuscated mapping content:
{
 "ip": {
    "10.203.195.4": "42.42.1.2",
    "10.203.192.91": "42.42.2.3",
    "10.203.192.94": "42.42.3.4",
    "0.0.0.0": "42.42.4.5",
    "169.254.169.254": "42.42.5.6",
    "127.0.0.1": "42.42.6.7",
    ...
  },
 "domain": {
    "sap.internal": "domain_0",
    "google.internal": "domain_1",
    "customer.net": "domain_2",
    "szg-dec-org-sap.internal": "domain_3",
    "west3-prd-prj-sap.internal": "domain_4",
    "suse.de": "domain_5",
    "example.com": "domain_6",
    ...
  },
 "user": {
    "ron": "user_0",
    "alex": "user_1",
    "nobody": "user_2",
    "root": "user_3",
    "g3padm": "user_4",
    "j3padm": "user_5",
    "admin_atharva: "user_6",
    ...
  },
 "hostname": {
    "metadata": "hostname_0",
    "szg2658": "hostname_1",
    "sz2657": "hostname_2",
    "SDP3": "hostname_3",
    "SVTF3": "hostname_4",
    "smt-gce": "hostname_15",
    "zitrone": "hostname_16",
    "terminus": "hostname_17"
    ...
  },
  
  "keyword": {},
  "mac": {},
  "ipv6": {}
 
}
