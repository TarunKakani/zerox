import os
import re
import shutil
import subprocess
from collections import Counter
from datetime import datetime
from typing import Dict, List, Optional, Tuple


FAILED_SSH_RE = re.compile(r"Failed password .* from (?P<ip>[0-9a-fA-F:.]+)")
ROOT_SUCCESS_RE = re.compile(r"(Accepted \S+ for root from (?P<ip>[0-9a-fA-F:.]+))|session opened for user root")
SUCCESS_RE = re.compile(r"Accepted \S+ for (?P<user>[a-zA-Z0-9._-]+) from (?P<ip>[0-9a-fA-F:.]+)")
JOURNAL_HOUR_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T(?P<hour>\d{2}):\d{2}:\d{2})")
SYSLOG_HOUR_RE = re.compile(r"^[A-Z][a-z]{2}\s+\d+\s+(?P<hour>\d{2}):\d{2}:\d{2}")


def _check(check_id: str, status: str, message: str, fix: str = None, details: str = None) -> Dict[str, str]:
    item = {"id": check_id, "status": status, "message": message}
    if fix:
        item["fix"] = fix
    if details:
        item["details"] = details
    return item


def _load_auth_lines() -> Tuple[List[str], str]:
    if shutil.which("journalctl"):
        proc = subprocess.run(
            ["journalctl", "--since", "24 hours ago", "-o", "short-iso", "--no-pager"],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.splitlines(), "journalctl"

    for path in ("/var/log/auth.log", "/var/log/secure"):
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                return handle.read().splitlines(), path
    return [], "none"


def _line_hour(line: str) -> Optional[int]:
    journal_match = JOURNAL_HOUR_RE.match(line)
    if journal_match:
        return int(journal_match.group("hour"))
    syslog_match = SYSLOG_HOUR_RE.match(line)
    if syslog_match:
        return int(syslog_match.group("hour"))
    return None


def _outside_window(hour: int, start: int, end: int) -> bool:
    if start == end:
        return False
    if start < end:
        return not (start <= hour < end)
    return not (hour >= start or hour < end)


def run_scan(logger, policy: Dict[str, object] = None, **_: Dict[str, object]) -> Dict[str, List[Dict[str, str]]]:
    checks: List[Dict[str, str]] = []
    policy = policy or {}
    failed_threshold = int(policy.get("auth_failed_threshold", 5))
    admin_hours = policy.get("admin_login_hours", {})
    start_hour = int(admin_hours.get("start", 0)) if isinstance(admin_hours, dict) else 0
    end_hour = int(admin_hours.get("end", 0)) if isinstance(admin_hours, dict) else 0

    lines, source = _load_auth_lines()
    if not lines:
        logger.warn("No auth logs were available for anomaly scan.")
        checks.append(_check("authlog-source", "warn", "No auth logs available for anomaly scan."))
        return {"name": "authlogs", "checks": checks}

    logger.info(f"Analyzing authentication events from {source}.")
    checks.append(_check("authlog-source", "info", f"Analyzed auth events from {source}."))

    failed_by_ip: Counter[str] = Counter()
    root_successes = 0
    off_hours_successes = 0
    success_samples: List[str] = []

    for line in lines:
        failed = FAILED_SSH_RE.search(line)
        if failed:
            failed_by_ip[failed.group("ip")] += 1

        if ROOT_SUCCESS_RE.search(line):
            root_successes += 1

        success = SUCCESS_RE.search(line)
        if success:
            hour = _line_hour(line)
            if hour is not None and _outside_window(hour, start_hour, end_hour):
                off_hours_successes += 1
                if len(success_samples) < 10:
                    success_samples.append(line.strip())

    noisy_sources = {ip: count for ip, count in failed_by_ip.items() if count >= failed_threshold}
    if noisy_sources:
        logger.warn(f"Repeated failed SSH attempts detected from {len(noisy_sources)} source IP(s).")
        details = "; ".join(f"{ip}:{count}" for ip, count in sorted(noisy_sources.items(), key=lambda item: item[1], reverse=True)[:20])
        checks.append(
            _check(
                "authlog-failed-ssh",
                "warn",
                f"Repeated failed SSH attempts detected from {len(noisy_sources)} source IP(s).",
                details=details,
                fix="Block abusive sources and validate SSH hardening (MFA, keys-only, fail2ban).",
            )
        )
    else:
        checks.append(_check("authlog-failed-ssh", "pass", "No repeated failed SSH sources exceeded threshold."))

    if root_successes:
        logger.warn(f"Detected {root_successes} successful root authentication event(s).")
        checks.append(
            _check(
                "authlog-root-success",
                "warn",
                f"Detected {root_successes} successful root authentication event(s).",
                fix="Restrict direct root login and review privileged session provenance.",
            )
        )
    else:
        checks.append(_check("authlog-root-success", "pass", "No successful root authentication events detected."))

    if isinstance(admin_hours, dict) and "start" in admin_hours and "end" in admin_hours:
        if off_hours_successes:
            logger.warn(f"Detected {off_hours_successes} successful login(s) outside configured admin hours.")
            checks.append(
                _check(
                    "authlog-offhours-success",
                    "warn",
                    f"{off_hours_successes} successful login(s) occurred outside admin hours {start_hour:02d}:00-{end_hour:02d}:00.",
                    details="; ".join(success_samples),
                    fix="Review whether off-hours access was expected and update alerting if needed.",
                )
            )
        else:
            checks.append(
                _check(
                    "authlog-offhours-success",
                    "pass",
                    f"No successful logins outside admin hours {start_hour:02d}:00-{end_hour:02d}:00.",
                )
            )
    else:
        checks.append(
            _check(
                "authlog-offhours-config",
                "skip",
                "No admin_login_hours configured in policy; off-hours login analysis skipped.",
            )
        )

    checks.append(
        _check(
            "authlog-scan-time",
            "info",
            f"Authentication anomaly summary generated at {datetime.utcnow().isoformat()}Z.",
        )
    )

    return {"name": "authlogs", "checks": checks}
