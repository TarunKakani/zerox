import glob
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Dict, List


CRITICAL_BASELINE_PATHS = [
    "/etc/ssh/sshd_config",
    "/etc/sudoers",
    "/etc/sysctl.conf",
    "/etc/pam.d",
]


def _check(check_id: str, status: str, message: str, fix: str = None, details: str = None) -> Dict[str, str]:
    item = {"id": check_id, "status": status, "message": message}
    if fix:
        item["fix"] = fix
    if details:
        item["details"] = details
    return item


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _collect_targets() -> List[str]:
    targets: List[str] = []
    for item in CRITICAL_BASELINE_PATHS:
        if os.path.isdir(item):
            for nested in sorted(glob.glob(os.path.join(item, "*"))):
                if os.path.isfile(nested):
                    targets.append(nested)
        else:
            targets.append(item)
    return sorted(set(targets))


def _snapshot_targets() -> Dict[str, Dict[str, str]]:
    snapshot: Dict[str, Dict[str, str]] = {}
    for path in _collect_targets():
        if not os.path.exists(path):
            snapshot[path] = {"exists": False}
            continue
        if not os.path.isfile(path):
            snapshot[path] = {"exists": True, "type": "non-file"}
            continue
        try:
            snapshot[path] = {"exists": True, "sha256": _sha256_file(path)}
        except PermissionError:
            snapshot[path] = {"exists": True, "error": "permission-denied"}
        except OSError:
            snapshot[path] = {"exists": True, "error": "read-failed"}
    return snapshot


def _write_baseline(path: str, entries: Dict[str, Dict[str, str]]) -> None:
    payload = {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "entries": entries,
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def run_scan(
    logger,
    baseline_path: str = "zerox_baseline.json",
    init_baseline: bool = False,
    **_: Dict[str, object],
) -> Dict[str, List[Dict[str, str]]]:
    checks: List[Dict[str, str]] = []
    current = _snapshot_targets()

    if init_baseline:
        _write_baseline(baseline_path, current)
        logger.fixed(f"Baseline initialized at {baseline_path}.")
        checks.append(_check("baseline-init", "fixed", f"Baseline initialized at {baseline_path}."))
        return {"name": "baseline", "checks": checks}

    if not os.path.exists(baseline_path):
        message = f"Baseline file not found: {baseline_path}."
        logger.warn(message)
        checks.append(
            _check(
                "baseline-missing",
                "warn",
                message,
                fix=f"Run with --init-baseline to create {baseline_path}.",
            )
        )
        return {"name": "baseline", "checks": checks}

    try:
        with open(baseline_path, "r", encoding="utf-8") as handle:
            baseline = json.load(handle)
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON baseline file: {baseline_path}.")
        checks.append(_check("baseline-json", "error", f"Invalid JSON in {baseline_path}."))
        return {"name": "baseline", "checks": checks}

    baseline_entries = baseline.get("entries", {})
    if not isinstance(baseline_entries, dict):
        logger.error(f"Baseline entries are malformed in {baseline_path}.")
        checks.append(_check("baseline-format", "error", f"Malformed entries in {baseline_path}."))
        return {"name": "baseline", "checks": checks}

    drift_count = 0
    for path, expected in sorted(baseline_entries.items()):
        expected_exists = expected.get("exists", False)
        actual = current.get(path, {"exists": False})
        actual_exists = actual.get("exists", False)
        if expected_exists != actual_exists:
            drift_count += 1
            logger.fail(f"Baseline drift: {path} existence changed (expected {expected_exists}, got {actual_exists}).")
            checks.append(
                _check(
                    f"baseline-{path}",
                    "fail",
                    f"{path} existence changed from baseline.",
                )
            )
            continue
        if not expected_exists:
            checks.append(_check(f"baseline-{path}", "pass", f"{path} remains absent as baseline expects."))
            continue
        if expected.get("error") or actual.get("error"):
            checks.append(
                _check(
                    f"baseline-{path}",
                    "warn",
                    f"{path} could not be hashed consistently (baseline={expected.get('error', 'ok')} current={actual.get('error', 'ok')}).",
                    fix="Run baseline drift checks as root for full hash coverage.",
                )
            )
            continue
        expected_hash = expected.get("sha256")
        actual_hash = actual.get("sha256")
        if expected_hash != actual_hash:
            drift_count += 1
            logger.fail(f"Baseline drift detected for {path}.")
            checks.append(
                _check(
                    f"baseline-{path}",
                    "fail",
                    f"Hash drift detected for {path}.",
                    fix=f"Review changes; if expected, re-run with --init-baseline to refresh {baseline_path}.",
                )
            )
        else:
            checks.append(_check(f"baseline-{path}", "pass", f"{path} matches baseline hash."))

    new_targets = sorted(set(current.keys()) - set(baseline_entries.keys()))
    if new_targets:
        logger.warn(f"New tracked files not present in baseline: {len(new_targets)}.")
        checks.append(
            _check(
                "baseline-new-targets",
                "warn",
                f"{len(new_targets)} tracked files are not present in the baseline.",
                details="; ".join(new_targets[:25]),
                fix=f"Review and refresh baseline with --init-baseline if these files are expected.",
            )
        )

    if drift_count == 0:
        logger.passed("No baseline drift detected in tracked critical configs.")
        checks.append(_check("baseline-drift-summary", "pass", "No baseline drift detected in tracked critical configs."))
    else:
        checks.append(_check("baseline-drift-summary", "fail", f"Detected {drift_count} baseline drift item(s)."))

    return {"name": "baseline", "checks": checks}
