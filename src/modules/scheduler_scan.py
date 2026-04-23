import glob
import os
import shlex
import stat
from typing import Dict, List, Set


CRON_PATHS = [
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
]


def _check(check_id: str, status: str, message: str, fix: str = None, details: str = None) -> Dict[str, str]:
    item = {"id": check_id, "status": status, "message": message}
    if fix:
        item["fix"] = fix
    if details:
        item["details"] = details
    return item


def _iter_cron_files() -> List[str]:
    files: List[str] = []
    for path in CRON_PATHS:
        if os.path.isfile(path):
            files.append(path)
            continue
        if os.path.isdir(path):
            files.extend(sorted(item for item in glob.glob(os.path.join(path, "*")) if os.path.isfile(item)))
    return sorted(set(files))


def _is_world_writable(path: str) -> bool:
    return bool(os.stat(path).st_mode & stat.S_IWOTH)


def _extract_cron_command(path: str, line: str) -> str:
    fields = line.split()
    if path.endswith("crontab") or "/cron.d/" in path:
        if len(fields) < 7:
            return ""
        return " ".join(fields[6:])
    if len(fields) < 6:
        return ""
    return " ".join(fields[5:])


def _command_binary(command: str) -> str:
    if not command:
        return ""
    try:
        token = shlex.split(command)[0]
    except ValueError:
        return ""
    return token


def _collect_timer_files() -> List[str]:
    timer_files: List[str] = []
    if os.path.isdir("/etc/systemd/system"):
        for root, _, files in os.walk("/etc/systemd/system"):
            for filename in files:
                if filename.endswith(".timer"):
                    timer_files.append(os.path.join(root, filename))
    return sorted(set(timer_files))


def _unit_for_timer(timer_path: str) -> str:
    unit_name = os.path.basename(timer_path).replace(".timer", ".service")
    configured_unit = ""
    with open(timer_path, "r", encoding="utf-8", errors="ignore") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("Unit="):
                configured_unit = line.split("=", 1)[1].strip()
    return configured_unit or unit_name


def _extract_execstarts(unit_path: str) -> List[str]:
    exec_lines: List[str] = []
    with open(unit_path, "r", encoding="utf-8", errors="ignore") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("ExecStart="):
                exec_lines.append(line.split("=", 1)[1].strip())
    return exec_lines


def run_scan(logger, **_: Dict[str, object]) -> Dict[str, List[Dict[str, str]]]:
    checks: List[Dict[str, str]] = []
    cron_files = _iter_cron_files()
    if not cron_files:
        logger.warn("No standard cron files found to audit.")
        checks.append(_check("scheduler-cron-files", "warn", "No standard cron files found to audit."))
    else:
        checks.append(_check("scheduler-cron-files", "info", f"Audited {len(cron_files)} cron file(s)."))

    insecure_schedule_files: List[str] = []
    writable_job_targets: Set[str] = set()

    for path in cron_files:
        try:
            stats = os.stat(path)
        except (FileNotFoundError, PermissionError):
            continue

        if stats.st_uid != 0 or _is_world_writable(path):
            insecure_schedule_files.append(path)

        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                command = _extract_cron_command(path, line)
                binary = _command_binary(command)
                if not binary or not binary.startswith("/"):
                    continue
                if os.path.exists(binary) and _is_world_writable(binary):
                    writable_job_targets.add(binary)

    timer_files = _collect_timer_files()
    for timer_path in timer_files:
        try:
            if _is_world_writable(timer_path):
                insecure_schedule_files.append(timer_path)
            unit_name = _unit_for_timer(timer_path)
            unit_path = os.path.join("/etc/systemd/system", unit_name)
            if not os.path.exists(unit_path):
                continue
            if _is_world_writable(unit_path):
                insecure_schedule_files.append(unit_path)
            for exec_cmd in _extract_execstarts(unit_path):
                binary = _command_binary(exec_cmd)
                if binary.startswith("/") and os.path.exists(binary) and _is_world_writable(binary):
                    writable_job_targets.add(binary)
        except PermissionError:
            continue

    if insecure_schedule_files:
        logger.fail(f"Found insecure cron/timer definitions: {len(insecure_schedule_files)}.")
        checks.append(
            _check(
                "scheduler-insecure-files",
                "fail",
                f"Found insecure cron/timer definitions ({len(insecure_schedule_files)}).",
                details="; ".join(sorted(set(insecure_schedule_files))[:25]),
                fix="Ensure schedule files are root-owned and not world-writable.",
            )
        )
    else:
        logger.passed("Cron and timer definition file permissions look safe.")
        checks.append(_check("scheduler-insecure-files", "pass", "No insecure cron/timer definition files found."))

    if writable_job_targets:
        logger.fail(f"Found scheduled jobs executing from writable paths: {len(writable_job_targets)}.")
        checks.append(
            _check(
                "scheduler-writable-targets",
                "fail",
                f"Found scheduled jobs executing writable binaries/scripts ({len(writable_job_targets)}).",
                details="; ".join(sorted(writable_job_targets)[:25]),
                fix="Move jobs to root-owned non-writable paths and tighten file permissions.",
            )
        )
    else:
        logger.passed("No scheduled jobs point to world-writable executable paths.")
        checks.append(_check("scheduler-writable-targets", "pass", "No writable scheduled-job targets detected."))

    return {"name": "scheduler", "checks": checks}
