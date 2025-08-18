# pcap_rewrite.py

import ipaddress
import shutil
import subprocess
import os

def _only_ipv4_pairs(subnet_dict):
    """Return [(src_cidr, dst_cidr), ...] for valid IPv4 CIDR pairs only."""
    pairs = []
    if not subnet_dict:
        return pairs
    for src, dst in subnet_dict.items():
        try:
            s = ipaddress.ip_network(src, strict=False)
            d = ipaddress.ip_network(dst, strict=False)
            if s.version == 4 and d.version == 4 and s.prefixlen == d.prefixlen:
                pairs.append((str(s), str(d)))
        except Exception:
            continue
    return pairs

def _sort_most_specific_first(pairs):
    """Sort by descending prefixlen, then lexicographically for stability."""
    def keyfn(item):
        net = ipaddress.ip_network(item[0], strict=False)
        return (net.prefixlen, item[0], item[1])
    return sorted(pairs, key=keyfn, reverse=True)

def _rules_table_lines(pairs):
    """Build aligned lines 'SRC -> DST' for printing."""
    if not pairs:
        return []
    left_w = max(len(a) for a, _ in pairs)
    lines = []
    for a, b in pairs:
        lines.append(f"  {a.ljust(left_w)}  ->  {b}")
    return lines

def _compose_ipmap_arg(pairs):
    """Return 'a:b,c:d,...' string for --srcipmap/--dstipmap."""
    return ",".join([f"{a}:{b}" for a, b in pairs])

def _dest_paths(out_dir, fin):
    base = os.path.basename(fin)
    root, ext = os.path.splitext(base)
    if not ext:
        ext = ".pcap"
    fout = os.path.join(out_dir, f"{root}_scrubbed{ext}")
    tmp  = f"{fout}.tmp"
    return tmp, fout

def rewrite_pcaps_with_tcprewrite(mappings, pcap_inputs, out_dir, *,
                                  tcprewrite="tcprewrite", print_cmd=False, logger=None):
    """
    Rewrite PCAPs using IPv4 subnet mappings (most-specific first).
    - Shows a tidy table of translations to reassure users.
    - One tcprewrite call per input file (originals untouched).
    - Output: <name>_scrubbed.<ext> in out_dir, perms/mtime preserved.
    """
    os.makedirs(out_dir, exist_ok=True)

    v4_pairs = _only_ipv4_pairs(mappings.get("subnet") or {})
    v4_rules = _sort_most_specific_first(v4_pairs)

    print("\n[INFO] Using --rewrite-pcap: original pcaps will remain untouched;")
    print("       rewritten copies are saved with suffix _scrubbed.pcap in the chosen output directory.\n")

    print("=== PCAP rewrite mode (IPv4 only) ===")
    print(f"- Input files      : {', '.join(os.path.basename(x) for x in pcap_inputs)}")
    print(f"- Output directory : {os.path.abspath(out_dir)}")
    print(f"- IPv4 rules found : {len(v4_rules)}\n")

    if not v4_rules:
        print("No IPv4 'subnet' rules present in mappings. Nothing to rewrite.")
        return

    print("IPv4 subnet rewrite rules (most-specific first):")
    for line in _rules_table_lines(v4_rules):
        print(line)
    print()

    ipmap = _compose_ipmap_arg(v4_rules)

    for fin in pcap_inputs:
        tmp, fout = _dest_paths(out_dir, fin)

        if print_cmd:
            print("tcprewrite command:")
            print(f"  {tcprewrite} \\")
            print(f"    --srcipmap={ipmap} \\")
            print(f"    --dstipmap={ipmap} \\")
            print(f"    -i {fin} \\")
            print(f"    -o {tmp}\n")

        cmd = [
            tcprewrite,
            f"--srcipmap={ipmap}",
            f"--dstipmap={ipmap}",
            "-i", fin,
            "-o", tmp,
        ]

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            msg = f"tcprewrite failed on {fin}: {e}"
            if logger:
                logger.error(msg)
            else:
                print(f"ERROR: {msg}")
            raise

        os.replace(tmp, fout)
        try:
            shutil.copystat(fin, fout)
            os.chmod(fout, 0o644)
        except Exception:
            pass

        print(f"[✓] Rewrote pcap file:: {fout}\n")
