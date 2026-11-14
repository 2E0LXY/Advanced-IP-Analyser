#!/usr/bin/env python3
"""ShipProof zero-dependency verification runner. Commands are trusted repo config."""
from __future__ import annotations
import argparse
import datetime as dt
import glob
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

STAGES = ("change", "pr", "merge", "release")

def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()

def run(stage: str, config_file: Path, report_dir: Path) -> int:
    root = config_file.resolve().parent
    config = json.loads(config_file.read_text(encoding="utf-8"))
    if config.get("schema_version") != 1:
        raise ValueError("Unsupported shipproof.json schema_version")
    checks = config.get("checks", [])
    if not isinstance(checks, list):
        raise ValueError("checks must be an array")
    results = []
    for check in checks:
        if stage not in check.get("stages", []):
            continue
        argv = check.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x for x in argv):
            raise ValueError(f"Invalid argv for check {check.get('id')}")
        start = time.monotonic()
        timeout = min(max(int(check.get("timeout_seconds", 180)), 1), 1800)
        try:
            p = subprocess.run(argv, cwd=root, capture_output=True, text=True, errors="replace", timeout=timeout, shell=False)
            status = "PASS" if p.returncode == 0 else "FAIL"
            output = (p.stdout + "\n" + p.stderr)[-12000:]
        except subprocess.TimeoutExpired:
            status, output = "FAIL", f"Timed out after {timeout} seconds"
        except (OSError, ValueError) as exc:
            status, output = "FAIL", str(exc)
        results.append({"id": check["id"], "required": bool(check.get("required", True)), "status": status,
                        "duration_seconds": round(time.monotonic() - start, 2), "output_tail": output})
        print(f"{status:6} {check['id']}")
    if not results:
        results.append({"id": "configuration", "required": True, "status": "UNVERIFIED", "output_tail": "No checks configured for stage"})
    files = []
    if stage == "release":
        for pattern in config.get("required_artifacts", []):
            matches = [Path(p) for p in glob.glob(str(root / pattern), recursive=True) if Path(p).is_file()]
            if not matches:
                results.append({"id": f"artifact:{pattern}", "required": True, "status": "UNVERIFIED", "output_tail": "Required artifact missing"})
            for match in matches:
                files.append({"path": str(match.relative_to(root)), "sha256": sha256(match), "size": match.stat().st_size})
    commit = "UNVERIFIED"
    try:
        p = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=10)
        if p.returncode == 0 and len(p.stdout.strip()) == 40:
            commit = p.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    ok = bool(results) and all(r["status"] == "PASS" for r in results if r["required"])
    if stage == "release" and not config.get("required_artifacts"):
        ok = False
        results.append({"id": "release-artifacts-not-configured", "required": True, "status": "UNVERIFIED", "output_tail": "Configure required_artifacts"})
    report = {"schema_version": 1, "project": config.get("project", root.name), "stage": stage,
              "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "commit": commit,
              "status": "PASS" if ok else "FAIL", "checks": results, "artifacts": files,
              "note": "Automated checks only; hardware/manual acceptance requires separate evidence."}
    destination = (root / report_dir) if not report_dir.is_absolute() else report_dir
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    summary = [f"# ShipProof {stage}: {report['status']}", "", f"Project: {report['project']}", f"Commit: {commit}", "", "| Check | Status | Required |", "|---|---|---|"]
    summary.extend(f"| {r['id']} | {r['status']} | {r['required']} |" for r in results)
    summary += ["", "Artifacts:", *(f"- `{a['path']}` SHA256 `{a['sha256']}`" for a in files)]
    (destination / "report.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    print(f"ShipProof stage {stage}: {'PASS' if ok else 'FAIL'}; evidence: {destination}")
    return 0 if ok else 1

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", required=True, choices=STAGES)
    parser.add_argument("--config", default="shipproof.json", type=Path)
    parser.add_argument("--report-dir", default=".shipproof", type=Path)
    args = parser.parse_args()
    try:
        return run(args.stage, args.config, args.report_dir)
    except (OSError, ValueError, json.JSONDecodeError, KeyError) as exc:
        print(f"ShipProof configuration error: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
