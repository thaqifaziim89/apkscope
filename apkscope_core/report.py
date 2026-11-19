"""Console output and local report files (JSON + TXT).

Reports are written ONLY to the local output directory, inside a folder
named after the package and timestamp so every run is clearly labelled.
"""

import json
import os
import re
import sys
from datetime import datetime

from . import __version__

COLORS = {"High": "\033[91m", "Medium": "\033[93m", "Low": "\033[96m",
          "Info": "\033[90m", "bold": "\033[1m", "reset": "\033[0m"}


def _use_color(enabled):
    return enabled and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def paint(text, key, color=True):
    if not _use_color(color):
        return text
    return f"{COLORS[key]}{text}{COLORS['reset']}"


def print_summary(manifest, findings, score, rating, color=True):
    print()
    print(paint("=" * 78, "bold", color))
    print(paint(f" APKScope results: {manifest.package}", "bold", color))
    print(paint("=" * 78, "bold", color))
    print(f" App name     : {manifest.app_name}")
    print(f" Version      : {manifest.version_name} (code {manifest.version_code})")
    print(f" min / target : {manifest.min_sdk} / {manifest.target_sdk}")
    print(f" Permissions  : {len(manifest.permissions())}")
    print(f" Risk score   : {score}/100 ({rating})")
    print("-" * 78)
    if not findings:
        print(" [OK] No manifest issues found by the current checks.")
    for i, f in enumerate(findings, 1):
        tag = paint(f"[{f.severity:<6}]", f.severity, color)
        print(f" {i:>2}. {tag} {f.check_id} {f.title}")
        if f.component != "-":
            print(f"            component: {f.component}")
    print("-" * 78)
    counts = {s: sum(1 for f in findings if f.severity == s) for s in ("High", "Medium", "Low", "Info")}
    print(" Totals: " + "  ".join(f"{k}={v}" for k, v in counts.items()))


def _safe_name(text):
    return re.sub(r"[^A-Za-z0-9._-]", "_", text)[:80] or "unknown"


def build_report(manifest, findings, score, rating, completed, aborted):
    return {
        "tool": f"APKScope v{__version__}",
        "classification": "CONFIDENTIAL - authorized assessment results",
        "status": "ABORTED (partial results)" if aborted else "COMPLETE",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "target_file": os.path.basename(manifest.source),
        "package": manifest.package,
        "app_name": manifest.app_name,
        "version_name": manifest.version_name,
        "version_code": manifest.version_code,
        "min_sdk": manifest.min_sdk,
        "target_sdk": manifest.target_sdk,
        "risk_score": score,
        "risk_rating": rating,
        "checks_completed": completed,
        "permissions": manifest.permissions(),
        "total_findings": len(findings),
        "findings": [f.to_dict() for f in findings],
    }


def save_report(report, output_dir):
    """Write report.json and report.txt into output/<package>_<timestamp>/."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(output_dir, f"{_safe_name(report['package'])}_{stamp}")
    os.makedirs(run_dir, exist_ok=True)

    json_path = os.path.join(run_dir, "report.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    txt_path = os.path.join(run_dir, "report.txt")
    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write(f"{report['tool']} - {report['classification']}\n")
        fh.write("=" * 70 + "\n")
        for key in ("status", "generated_at", "target_file", "package", "app_name",
                    "version_name", "min_sdk", "target_sdk"):
            fh.write(f"{key:<14}: {report[key]}\n")
        fh.write(f"{'risk':<14}: {report['risk_score']}/100 ({report['risk_rating']})\n")
        fh.write("=" * 70 + "\n\n")
        for i, f in enumerate(report["findings"], 1):
            fh.write(f"{i}. [{f['severity']}] {f['check_id']} {f['title']}\n")
            if f["component"] != "-":
                fh.write(f"   Component     : {f['component']}\n")
            fh.write(f"   Detail        : {f['detail']}\n")
            fh.write(f"   Recommendation: {f['recommendation']}\n")
            fh.write(f"   Reference     : {f['reference']}\n\n")
        fh.write("Handle this report according to the Responsible Disclosure section "
                 "of the README.\n")
    return run_dir
