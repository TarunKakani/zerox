import glob
import os
import re
from typing import Dict, List, Tuple


NOPASSWD_ALL_RE = re.compile(r"\bNOPASSWD:\s*ALL\b")
FULL_ROOT_RE = re.compile(r"=\s*\(ALL(?::ALL)?\)\s*ALL\b")


def _check(check_id: str, status: str, message: str, cis: str = None, fix: str = None, details: str = None) -> Dict[str, str]:
    item = {"id": check_id, "status": status, "message": message}
    if cis:
        item["cis"] = cis
    if fix:
        item["fix"] = fix
    if details:
        item["details"] = details
    return item


def _sudoers_files() -> List[str]:
    files = ["/etc/sudoers"]
    if os.path.isdir("/etc/sudoers.d"):
        files.extend(sorted(path for path in glob.glob("/etc/sudoers.d/*") if os.path.isfile(path)))
    return files


def _active_lines(path: str) -> List[Tuple[int, str]]:
    rows: List[Tuple[int, str]] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for index, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("Defaults"):
                continue
            rows.append((index, line))
    return rows


def _has_wildcard_command(line: str) -> bool:
    if ":" not in line:
        return False
    command_section = line.split(":", 1)[1].strip()
    return "*" in command_section


def run_scan(logger, **_: Dict[str, object]) -> Dict[str, List[Dict[str, str]]]:
    checks: List[Dict[str, str]] = []
    files = _sudoers_files()
    if not files:
        logger.error("Could not locate sudoers files.")
        checks.append(_check("sudoers-files", "error", "No sudoers files found."))
        return {"name": "sudoers", "checks": checks}

    nopasswd_all_hits: List[str] = []
    broad_root_hits: List[str] = []
    wildcard_hits: List[str] = []

    for path in files:
        try:
            for line_number, line in _active_lines(path):
                marker = f"{path}:{line_number}"
                if NOPASSWD_ALL_RE.search(line):
                    nopasswd_all_hits.append(marker)
                if FULL_ROOT_RE.search(line):
                    broad_root_hits.append(marker)
                if _has_wildcard_command(line):
                    wildcard_hits.append(marker)
        except PermissionError:
            logger.error(f"Permission denied reading {path}.")
            checks.append(_check(f"sudoers-read-{path}", "error", f"Permission denied reading {path}."))

    if nopasswd_all_hits:
        logger.fail(f"Found NOPASSWD:ALL entries in sudoers: {len(nopasswd_all_hits)}.")
        checks.append(
            _check(
                "sudoers-nopasswd-all",
                "fail",
                f"Detected NOPASSWD:ALL entries ({len(nopasswd_all_hits)}).",
                cis="CIS Benchmark 5.2.x",
                details="; ".join(nopasswd_all_hits[:20]),
                fix="Restrict NOPASSWD usage to specific commands and principals.",
            )
        )
    else:
        logger.passed("No NOPASSWD:ALL entries found in sudoers policy.")
        checks.append(_check("sudoers-nopasswd-all", "pass", "No NOPASSWD:ALL entries found."))

    if broad_root_hits:
        logger.fail(f"Found broad full-root grants in sudoers: {len(broad_root_hits)}.")
        checks.append(
            _check(
                "sudoers-full-root",
                "fail",
                f"Detected broad full-root grants ({len(broad_root_hits)}).",
                details="; ".join(broad_root_hits[:20]),
                fix="Constrain sudo grants to least-privilege command sets.",
            )
        )
    else:
        logger.passed("No broad full-root sudo grants detected.")
        checks.append(_check("sudoers-full-root", "pass", "No broad full-root sudo grants detected."))

    if wildcard_hits:
        logger.warn(f"Found wildcard command grants in sudoers: {len(wildcard_hits)}.")
        checks.append(
            _check(
                "sudoers-wildcards",
                "warn",
                f"Detected wildcard command grants ({len(wildcard_hits)}).",
                details="; ".join(wildcard_hits[:20]),
                fix="Replace wildcard sudo command grants with explicit command paths.",
            )
        )
    else:
        logger.passed("No wildcard sudo command grants detected.")
        checks.append(_check("sudoers-wildcards", "pass", "No wildcard command grants detected."))

    return {"name": "sudoers", "checks": checks}
