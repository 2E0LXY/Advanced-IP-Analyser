#!/usr/bin/env python3
"""ShipProof: fail-closed milestone verification with inspectable evidence."""
from __future__ import annotations
import argparse
import datetime as dt
import glob
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

STAGES = ("change", "pr", "merge", "release")
SCHEMA = 1


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_argv(argv: list[str], *, windows: bool | None = None, locate=None) -> list[str]:
    """Resolve Windows .cmd shims (npm.cmd etc.) without shell=True."""
    win = os.name == "nt" if windows is None else windows
    if not win or Path(argv[0]).suffix:
        return list(argv)
    finder = shutil.which if locate is None else locate
    located = finder(argv[0] + ".cmd") or finder(argv[0] + ".exe") or finder(argv[0])
    return [located or argv[0], *argv[1:]]


def validate_config(config: dict, stage: str) -> None:
    if not isinstance(config, dict) or config.get("schema_version") != SCHEMA:
        raise ValueError("Unsupported shipproof.json schema_version")
    checks = config.get("checks")
    if not isinstance(checks, list):
        raise ValueError("checks must be an array")
    seen = set()
    for check in checks:
        if not isinstance(check, dict):
            raise ValueError("every check must be an object")
        ident = check.get("id")
        if not isinstance(ident, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,90}", ident):
            raise ValueError("invalid check id")
        if ident in seen:
            raise ValueError(f"duplicate check id: {ident}")
        seen.add(ident)
        stages = check.get("stages")
        if not isinstance(stages, list) or not stages or any(s not in STAGES for s in stages):
            raise ValueError(f"invalid stages for {ident}")
        if not isinstance(check.get("required", True), bool):
            raise ValueError(f"required must be boolean for {ident}")
        argv = check.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(s, str) and s and "\x00" not in s for s in argv):
            raise ValueError(f"invalid argv for {ident}")
        timeout = check.get("timeout_seconds", 180)
        if type(timeout) is not int or not (1 <= timeout <= 1800):
            raise ValueError(f"invalid timeout for {ident}")
        if "min_tests" in check and (type(check["min_tests"]) is not int or check["min_tests"] < 1):
            raise ValueError(f"invalid min_tests for {ident}")
        if "test_count_pattern" in check:
            pattern = check["test_count_pattern"]
            if "min_tests" not in check:
                raise ValueError(f"test_count_pattern requires min_tests for {ident}")
            try:
                compiled = re.compile(pattern) if isinstance(pattern, str) and pattern else None
            except re.error:
                compiled = None
            if compiled is None or compiled.groups < 1:
                raise ValueError(f"invalid test_count_pattern for {ident}: must be a valid regex with a capture group")
    patterns = config.get("required_artifacts", [])
    if not isinstance(patterns, list):
        raise ValueError("required_artifacts must be an array")
    for pattern in patterns:
        if not isinstance(pattern, str) or not pattern or Path(pattern).is_absolute() or ".." in Path(pattern).parts:
            raise ValueError("required artifact patterns must be relative and remain in the repository")
    min_size = config.get("min_artifact_bytes", 1)
    if type(min_size) is not int or min_size < 1:
        raise ValueError("min_artifact_bytes must be a positive integer")
    acceptance = config.get("acceptance", [])
    if not isinstance(acceptance, list):
        raise ValueError("acceptance must be an array")
    for requirement in acceptance:
        if not isinstance(requirement, dict) or not isinstance(requirement.get("id"), str):
            raise ValueError("invalid acceptance requirement")
        tests = requirement.get("checks")
        if not isinstance(tests, list) or not tests or any(t not in seen for t in tests):
            raise ValueError("acceptance checks must reference existing check ids")
        if not isinstance(requirement.get("required", True), bool):
            raise ValueError("acceptance required must be boolean")
    if config.get("require_acceptance", False) and not acceptance:
        raise ValueError("required acceptance criteria missing")


def _safe_log(text: str) -> str:
    """Do not place arbitrary command output or potentially leaked secrets in uploaded reports."""
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    return f"Command output withheld from uploaded report (sha256={digest})."


def _check_result(check: dict, root: Path) -> dict:
    begin = time.monotonic()
    status, exit_code, detail, observed = "FAIL", None, "", None
    try:
        p = subprocess.run(resolve_argv(check["argv"]), cwd=root, capture_output=True,
                           text=True, errors="replace", timeout=check.get("timeout_seconds", 180), shell=False)
        exit_code = p.returncode
        output = p.stdout + "\n" + p.stderr
        detail = _safe_log(output)
        status = "PASS" if exit_code == 0 else "FAIL"
        if "min_tests" in check:
            # For unittest, require a non-zero test count. For other runners use a custom evidence regex.
            regex = check.get("test_count_pattern", r"Ran (\d+) tests?")
            try:
                match = re.search(regex, output)
                observed = int(match.group(1)) if match else 0
            except (re.error, IndexError, ValueError, TypeError):
                # Fail closed: an unreadable test count never satisfies min_tests.
                status, observed = "FAIL", None
                detail = "Test count could not be parsed with test_count_pattern. " + detail
            if observed is not None and observed < check["min_tests"]:
                status = "FAIL"
                detail = f"Only {observed} tests observed; minimum {check['min_tests']}. " + detail
    except subprocess.TimeoutExpired:
        detail = f"Timed out after {check.get('timeout_seconds',180)} seconds"
    except (OSError, ValueError, re.error) as exc:
        detail = f"Could not execute check ({type(exc).__name__}); inspect local CI logs."
    return {"id": check["id"], "required": check.get("required", True),
            "status": status, "exit_code": exit_code, "duration_seconds": round(time.monotonic() - begin, 2),
            "tests_observed": observed, "detail": detail}


def _artifact_matches(root: Path, pattern: str, minimum: int) -> tuple[list[dict], str | None]:
    found = []
    for candidate in glob.glob(str(root / pattern), recursive=True):
        path = Path(candidate)
        if not path.is_file() or path.is_symlink():
            continue
        resolved = path.resolve()
        if not resolved.is_relative_to(root):
            return [], "Artifact path escapes project root"
        if path.stat().st_size < minimum:
            return [], f"Artifact smaller than minimum {minimum} bytes"
        found.append({"path": str(path.relative_to(root)), "sha256": sha256(path), "size": path.stat().st_size})
    if not found:
        return [], "Required release artefact was not found"
    return found, None


def run(stage: str, config_file: Path, report_dir: Path) -> int:
    if stage not in STAGES:
        raise ValueError("invalid stage")
    root = config_file.resolve().parent
    config = json.loads(config_file.read_text(encoding="utf-8"))
    validate_config(config, stage)
    required = [c for c in config["checks"] if stage in c["stages"] and c.get("required", True)]
    results = [_check_result(c, root) for c in config["checks"] if stage in c["stages"]]
    if not required:
        results.append({"id": "required-tests-not-configured", "required": True,
                        "status": "UNVERIFIED", "detail": "Stage has no required runnable checks"})
    files = []
    if stage == "release":
        if not config.get("required_artifacts"):
            results.append({"id": "release-artifacts-not-configured", "required": True,
                            "status": "UNVERIFIED", "detail": "No release artefacts declared"})
        for pattern in config.get("required_artifacts", []):
            matches, error = _artifact_matches(root, pattern, config.get("min_artifact_bytes", 1))
            files.extend(matches)
            results.append({"id": "artifact:"+pattern, "required": True, "status": "FAIL" if error else "PASS",
                            "detail": error or f"{len(matches)} artefact(s) hashed"})
    acceptance_results = []
    for requirement in config.get("acceptance", []):
        states = [next((r["status"] for r in results if r["id"] == test), "UNVERIFIED") for test in requirement["checks"]]
        status = "PASS" if states and all(s == "PASS" for s in states) else ("FAIL" if "FAIL" in states else "UNVERIFIED")
        acceptance_results.append({"id": requirement["id"], "status": status,
                                   "required": requirement.get("required", True), "checks": requirement["checks"]})
        if stage == "release" and requirement.get("required", True) and status != "PASS":
            results.append({"id": "acceptance:"+requirement["id"], "required": True,
                            "status": status, "detail": "Release acceptance criteria not verified"})
    commit = "UNVERIFIED"
    try:
        p = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=10)
        if p.returncode == 0 and re.fullmatch(r"[a-f0-9]{40}", p.stdout.strip()):
            commit = p.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    success = bool(required) and all(r["status"] == "PASS" for r in results if r["required"])
    report = {"schema_version": 1, "project": config.get("project", root.name), "stage": stage,
              "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "commit": commit,
              "status": "PASS" if success else "FAIL", "checks": results, "acceptance": acceptance_results,
              "acceptance_coverage": "DECLARED" if config.get("acceptance") else "NOT_DECLARED",
              "artifacts": files, "note": "A PASS certifies only declared automated checks, never full functionality or physical hardware."}
    destination = (root / report_dir) if not report_dir.is_absolute() else report_dir
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    summary = [f"# ShipProof {stage}: {report['status']}", "", f"Project: {report['project']}",
               f"Commit: {commit}", f"Acceptance coverage: {report['acceptance_coverage']}",
               "", "| Check | Status | Required |", "|---|---|---|"]
    summary.extend(f"| {r['id']} | {r['status']} | {r['required']} |" for r in results)
    summary.extend(["", "| Acceptance | Status |", "|---|---|"])
    summary.extend(f"| {r['id']} | {r['status']} |" for r in acceptance_results)
    summary += ["", "Artifacts:", *(f"- `{a['path']}` SHA256 `{a['sha256']}`" for a in files)]
    (destination / "report.md").write_text("\n".join(summary)+"\n", encoding="utf-8")
    print(f"ShipProof stage {stage}: {report['status']}; evidence: {destination}")
    for r in results:
        print(f"{r['status']:10} {r['id']}")
    return 0 if success else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", required=True, choices=STAGES)
    parser.add_argument("--config", default="shipproof.json", type=Path)
    parser.add_argument("--report-dir", default=".shipproof", type=Path)
    args = parser.parse_args()
    try:
        return run(args.stage, args.config, args.report_dir)
    except (OSError, ValueError, json.JSONDecodeError, KeyError, TypeError) as exc:
        print(f"ShipProof configuration error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
