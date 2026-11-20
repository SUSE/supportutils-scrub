"""--verify-output: check an already scrubbed tree or archive, scrub nothing.

The output of any run, of this tool or of another one, is checked against a
mapping: every real value the mapping holds must be gone from it. For the
output of another tool the mapping is the one a run of this tool on the same
original saved; that mapping is the list of what a scrub of that original
has to remove, whoever did the scrubbing.
"""

import os
import sys

from supportutils_scrub.audit import load_mappings_file, write_report
from supportutils_scrub.main import SCRIPT_VERSION, EXIT_VERIFY_FAIL
from supportutils_scrub.verify import verify_scrubbed_folder


def summarise(findings):
    """[(category, findings, occurrences, distinct values, files)], most first."""
    rows = {}
    for f in findings:
        r = rows.setdefault(str(f['category']), [0, 0, set(), set()])
        r[0] += 1
        r[1] += f.get('count', 1)
        r[2].add(f['value'])
        r[3].add(f['file'])
    return sorted(((c, r[0], r[1], len(r[2]), len(r[3])) for c, r in rows.items()),
                  key=lambda row: -row[2])


def run_check_mode(args, logger):
    target = args.verify_output.rstrip('/')
    if not os.path.exists(target):
        print(f"[!] --verify-output: no such file or directory: {target}", file=sys.stderr)
        sys.exit(2)
    if not args.mappings:
        print("[!] --verify-output needs --mappings: the mapping a run of this tool "
              "saved for the same original.", file=sys.stderr)
        sys.exit(2)
    mappings = load_mappings_file(args.mappings)
    originals = [p for p in args.supportconfig_path if os.path.isdir(p)]
    mapping_only = getattr(args, 'verify_mapping_only', False)
    findings = verify_scrubbed_folder(
        target, mappings, original_folder=originals[0] if originals else None,
        config=args._preloaded_config,
        check_allowlist=not mapping_only, check_patterns=not mapping_only,
        check_identity=bool(originals), jobs=args.jobs)

    out = sys.stdout
    if not findings:
        print(f"[\u2713] VERIFY: no sensitive data found in {target}", file=out)
    else:
        print(f"[!] VERIFY: {len(findings)} finding(s) in {target}", file=out)
        print(f"    {'category':<34}{'findings':>10}{'occurrences':>13}{'values':>8}{'files':>7}",
              file=out)
        for category, n, occ, values, files in summarise(findings):
            print(f"    {category:<34}{n:>10}{occ:>13}{values:>8}{files:>7}", file=out)
        if not getattr(args, 'quiet', False):
            for f in findings[:20]:
                print(f"    {f['file']}:{f['line']}  [{f['category']}]  {f['value']!r}", file=out)
            if len(findings) > 20:
                print(f"    ... and {len(findings) - 20} more (--report-file writes them all)",
                      file=out)
    if args.report_file:
        write_report(args.report_file, [{'input': os.path.abspath(target)}], SCRIPT_VERSION,
                     verify_findings=findings)
        print(f"    Report: {args.report_file}", file=out)
    if findings:
        sys.exit(EXIT_VERIFY_FAIL)
