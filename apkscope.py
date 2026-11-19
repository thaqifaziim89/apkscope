#!/usr/bin/env python3
"""APKScope - Android Manifest Security Analyzer (static analysis only).

IKB31603 Ethical Hacking - UniKL MIIT - Category: Mobile Application Attack
"""

import argparse
import os
import sys

from apkscope_core import __version__
from apkscope_core.checks import CHECKS, risk_score, run_checks
from apkscope_core.killswitch import EXIT_ABORTED, KillSwitch
from apkscope_core.loader import LoadError, load_target
from apkscope_core.report import build_report, print_summary, save_report
from apkscope_core.safety import confirm_authorization, enforce_scope

TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SCOPE = os.path.join(TOOL_DIR, "samples")
DEFAULT_TARGET = os.path.join(DEFAULT_SCOPE, "AndroidManifest_vulnerable.xml")
DEFAULT_OUTPUT = os.path.join(TOOL_DIR, "output")

EXAMPLES = """
examples:
  python apkscope.py                                  scan the bundled safe sample (default)
  python apkscope.py --dry-run                        show what would run, analyse nothing
  python apkscope.py samples/myapp.apk                scan an APK placed in samples/
  python apkscope.py C:\\tests\\app.apk -s C:\\tests    scan with a custom authorized scope
  python apkscope.py samples/app.apk -o reports       save reports to ./reports
  python apkscope.py --list-checks                    list all security checks

exit codes: 0 = done, 1 = not authorized / load error, 2 = out of scope, 130 = aborted (Ctrl+C)
"""


def build_parser():
    parser = argparse.ArgumentParser(
        prog="apkscope",
        description="APKScope v%s - static security audit of an Android APK's "
                    "AndroidManifest.xml. Never installs or runs the app." % __version__,
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", nargs="?", default=DEFAULT_TARGET,
                        help="APK file or decoded AndroidManifest .xml "
                             "(default: bundled vulnerable sample)")
    parser.add_argument("-s", "--scope", default=DEFAULT_SCOPE,
                        help="authorized folder; targets outside it are refused "
                             "(default: ./samples)")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT,
                        help="local folder for reports (default: ./output)")
    parser.add_argument("--dry-run", action="store_true",
                        help="validate target and scope, list checks, analyse nothing")
    parser.add_argument("--list-checks", action="store_true",
                        help="list the security checks and exit")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    parser.add_argument("-V", "--version", action="version", version=f"APKScope {__version__}")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if os.name == "nt":
        os.system("")  # enables ANSI colours in the Windows terminal
    color = not args.no_color

    if args.list_checks:
        for i, (label, check) in enumerate(CHECKS, 1):
            print(f" {i}. {label:<30} ({check.__name__})")
        return 0

    target = os.path.abspath(args.target)
    enforce_scope(target, args.scope)          # 1. scope before anything else
    if not os.path.isfile(target):
        print(f"[-] File not found: {target}")
        return 1

    if args.dry_run:
        print("[DRY-RUN] No file will be parsed and no report will be written.")
        print(f"  Target : {target}  (in scope)")
        print(f"  Output : {os.path.abspath(args.output)}")
        print("  Checks : " + ", ".join(label for label, _ in CHECKS))
        return 0

    if not confirm_authorization(target, os.path.realpath(args.scope)):   # 2. legal gate
        print("[!] Authorization not confirmed. Nothing was analysed.")
        return 1

    killswitch = KillSwitch()                   # 3. kill switch active from here
    killswitch.arm()

    try:
        manifest = load_target(target)
    except LoadError as exc:
        print(f"[-] {exc}")
        return 1

    print(f"[*] Static analysis of {os.path.basename(target)} ({manifest.package})")
    findings, completed, aborted = run_checks(
        manifest, killswitch, on_progress=lambda label: print(f"    - checking {label}"))

    score, rating = risk_score(findings)
    print_summary(manifest, findings, score, rating, color)
    report = build_report(manifest, findings, score, rating, completed, aborted)
    run_dir = save_report(report, args.output)
    print(f"\n[+] Reports saved locally (not uploaded anywhere): {run_dir}")

    if aborted:
        print("[!] Scan was ABORTED by the kill switch. Report is marked as partial.")
        return EXIT_ABORTED
    print("[+] Done. Follow the Rules of Engagement and Responsible Disclosure in the README.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
