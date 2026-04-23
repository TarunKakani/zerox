import glob
import os
import re
import stat
from typing import Dict, List, Set


STARTUP_FILES = [
    "/etc/rc.local",
    "/etc/ld.so.preload",
    "/etc/profile",
    "/etc/bash.bashrc",
]

STARTUP_PATTERNS = [
    "/etc/profile.d/*.sh",
    "/etc/systemd/system/*.service",
    "/etc/systemd/system/**/*.conf",
]

SUSPICIOUS_PATTERNS = [
    re.compile(r"\bcurl\b.*\|\s*(bash|sh)\b"),
    re.compile(r"\bwget\b.*\|\s*(bash|sh)\b"),
    re.compile(r"/tmp/"),
    re.compile(r"/dev/shm/"),
    re.compile(r"\bbase64\s+-d\b"),
    re.compile(r"\bnc\b|\bnetcat\b"),
    re.compile(r"\bpython\d?\s+-c\b"),
]


def _check(check_id: str, status: str, message: str, fix: str = None, details: str = None) -> Dict[str, str]:
    item = {"id": check_id, "status": status, "message": message}
    if fix:
        item["fix"] = fix
    if details:
        item["details"] = details
    return item


def _startup_files() -> List[str]:
    files: Set[str] = set(path for path in STARTUP_FILES if os.path.exists(path))
    for pattern in STARTUP_PATTERNS:
        files.update(path for path in glob.glob(pattern, recursive=True) if os.path.isfile(path))
    return sorted(files)


def _is_allowed(line: str, allowlist: List[str]) -> bool:
    return any(item in line for item in allowlist)


def _is_suspicious(line: str) -> bool:
    return any(pattern.search(line) for pattern in SUSPICIOUS_PATTERNS)


def run_scan(logger, policy: Dict[str, object] = None, **_: Dict[str, object]) -> Dict[str, List[Dict[str, str]]]:
    checks: List[Dict[str, str]] = []
    policy = policy or {}
    allowlist = [str(item) for item in policy.get("allowed_startup_entries", []) if str(item).strip()]

    files = _startup_files()
    if not files:
        logger.warn("No startup/persistence artifact files found in standard locations.")
        checks.append(_check("persistence-files", "warn", "No startup artifact files found in standard locations."))
        return {"name": "persistence", "checks": checks}

    suspicious_hits: List[str] = []
    writable_artifacts: List[str] = []
    preload_entries: List[str] = []

    for path in files:
        try:
            mode = os.stat(path).st_mode
            if mode & stat.S_IWOTH:
                writable_artifacts.append(path)
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                for line_number, raw in enumerate(handle, start=1):
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    if _is_allowed(line, allowlist):
                        continue
                    if path == "/etc/ld.so.preload":
                        preload_entries.append(f"{path}:{line_number}:{line}")
                        continue
                    if _is_suspicious(line):
                        suspicious_hits.append(f"{path}:{line_number}:{line}")
        except PermissionError:
            checks.append(_check(f"persistence-read-{path}", "error", f"Permission denied reading {path}."))

    if writable_artifacts:
        logger.fail(f"World-writable startup artifacts detected: {len(writable_artifacts)}.")
        checks.append(
            _check(
                "persistence-writable-files",
                "fail",
                f"World-writable startup artifacts detected ({len(writable_artifacts)}).",
                details="; ".join(writable_artifacts[:20]),
                fix="Remove world-write permissions from startup artifacts.",
            )
        )
    else:
        checks.append(_check("persistence-writable-files", "pass", "No world-writable startup artifacts detected."))

    if preload_entries:
        logger.warn("Entries found in /etc/ld.so.preload; validate they are expected.")
        checks.append(
            _check(
                "persistence-ld-preload",
                "warn",
                "Entries found in /etc/ld.so.preload.",
                details="; ".join(preload_entries[:10]),
                fix="Review ld.so preload entries and remove unexpected shared library hooks.",
            )
        )
    else:
        checks.append(_check("persistence-ld-preload", "pass", "No unexpected entries found in /etc/ld.so.preload."))

    if suspicious_hits:
        logger.warn(f"Suspicious startup entries detected: {len(suspicious_hits)}.")
        checks.append(
            _check(
                "persistence-suspicious-entries",
                "warn",
                f"Suspicious startup entries detected ({len(suspicious_hits)}).",
                details="; ".join(suspicious_hits[:20]),
                fix="Review and remove unauthorized persistence commands.",
            )
        )
    else:
        checks.append(_check("persistence-suspicious-entries", "pass", "No suspicious startup entries detected."))

    return {"name": "persistence", "checks": checks}
