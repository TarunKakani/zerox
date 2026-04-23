import os
import stat
import subprocess
from typing import Dict, List


CRITICAL_RULES = {
    "/etc/shadow": ["600", "400", "000"],
    "/etc/passwd": ["644"],
    "/boot/grub/grub.cfg": ["600", "400"],
}

CRITICAL_DIRS = ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/dev/shm"]


def _check(check_id: str, status: str, message: str, cis: str = None, fix: str = None, details: str = None) -> Dict[str, str]:
    item = {"id": check_id, "status": status, "message": message}
    if cis:
        item["cis"] = cis
    if fix:
        item["fix"] = fix
    if details:
        item["details"] = details
    return item


def _scan_world_writable(paths: List[str]) -> List[str]:
    vulnerable_items: List[str] = []
    for directory in paths:
        if not os.path.exists(directory):
            continue
        for root, dirs, files in os.walk(directory):
            for item in dirs + files:
                item_path = os.path.join(root, item)
                try:
                    mode = os.stat(item_path).st_mode
                    if mode & stat.S_IWOTH:
                        vulnerable_items.append(item_path)
                except (FileNotFoundError, PermissionError, OSError):
                    continue
    return vulnerable_items


def _scan_suid_files() -> List[str]:
    proc = subprocess.run(
        ["find", "/", "-perm", "-4000", "-type", "f"],
        capture_output=True,
        text=True,
    )
    if proc.returncode not in (0, 1):
        return []
    output = proc.stdout.strip()
    return output.splitlines() if output else []


def _parse_mounts() -> Dict[str, Dict[str, str]]:
    mounts: Dict[str, Dict[str, str]] = {}
    with open("/proc/mounts", "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            parts = line.split()
            if len(parts) < 4:
                continue
            mounts[parts[1]] = {"device": parts[0], "options": parts[3]}
    return mounts


def run_scan(logger, fix: bool = False, **_: Dict[str, str]) -> Dict[str, List[Dict[str, str]]]:
    checks: List[Dict[str, str]] = []

    for filepath, expected_modes in CRITICAL_RULES.items():
        try:
            actual_mode = stat.S_IMODE(os.stat(filepath).st_mode)
            actual_oct = oct(actual_mode)[2:]
            if actual_oct in expected_modes:
                logger.passed(f"{filepath} permissions are secure ({actual_oct}).")
                checks.append(_check(f"perm-{filepath}", "pass", f"{filepath} permissions are secure ({actual_oct})."))
            else:
                message = f"{filepath} has unsafe permissions {actual_oct}."
                logger.fail(message)
                checks.append(
                    _check(
                        f"perm-{filepath}",
                        "fail",
                        message,
                        cis="CIS Benchmark 6.1.x",
                        fix=f"Run: chmod {expected_modes[0]} {filepath}",
                    )
                )
                if fix:
                    try:
                        os.chmod(filepath, int(expected_modes[0], 8))
                        logger.fixed(f"Applied chmod {expected_modes[0]} {filepath}.")
                        checks.append(
                            _check(
                                f"perm-{filepath}-fixed",
                                "fixed",
                                f"Set {filepath} to mode {expected_modes[0]}.",
                            )
                        )
                    except PermissionError:
                        logger.error(f"Permission denied setting permissions on {filepath}.")
                        checks.append(_check(f"perm-{filepath}-fix-error", "error", f"Permission denied on {filepath}."))
        except FileNotFoundError:
            logger.warn(f"{filepath} does not exist on this system.")
            checks.append(_check(f"perm-{filepath}", "warn", f"{filepath} was not found."))
        except PermissionError:
            logger.error(f"Permission denied reading {filepath}.")
            checks.append(_check(f"perm-{filepath}", "error", f"Permission denied reading {filepath}."))

    bad_files = _scan_world_writable(CRITICAL_DIRS)
    if bad_files:
        logger.fail(f"Found {len(bad_files)} world-writable files/directories in critical paths.")
        checks.append(
            _check(
                "world-writable-critical",
                "fail",
                f"Found {len(bad_files)} world-writable entries in critical directories.",
                fix="Remove world-write bit from these files where not required.",
                details="; ".join(bad_files[:25]),
            )
        )
        if fix:
            fixed_count = 0
            for path in bad_files:
                try:
                    mode = os.stat(path).st_mode
                    os.chmod(path, mode & ~stat.S_IWOTH)
                    fixed_count += 1
                except (PermissionError, FileNotFoundError, OSError):
                    continue
            if fixed_count:
                logger.fixed(f"Removed world-write bit from {fixed_count} entries.")
                checks.append(_check("world-writable-critical-fixed", "fixed", f"Removed world-write bit from {fixed_count} entries."))
    else:
        logger.passed("No world-writable files found in critical directories.")
        checks.append(_check("world-writable-critical", "pass", "No world-writable entries in critical directories."))

    suid_files = _scan_suid_files()
    logger.info(f"Found {len(suid_files)} SUID binaries.")
    checks.append(
        _check(
            "suid-count",
            "info",
            f"Detected {len(suid_files)} SUID binaries.",
            details="; ".join(suid_files[:30]) if suid_files else None,
        )
    )

    mounts = _parse_mounts()
    for mountpoint in ("/tmp", "/var", "/home"):
        if mountpoint in mounts:
            logger.passed(f"{mountpoint} is mounted separately ({mounts[mountpoint]['device']}).")
            checks.append(_check(f"mount-{mountpoint}", "pass", f"{mountpoint} has a dedicated mount."))
        else:
            logger.warn(f"{mountpoint} is not mounted separately.")
            checks.append(
                _check(
                    f"mount-{mountpoint}",
                    "warn",
                    f"{mountpoint} is not on a separate mount.",
                    fix=f"Consider creating a dedicated {mountpoint} partition.",
                )
            )

    tmp_options = mounts.get("/tmp", {}).get("options", "")
    has_noexec = "noexec" in tmp_options.split(",")
    has_nosuid = "nosuid" in tmp_options.split(",")

    if has_noexec and has_nosuid:
        logger.passed("/tmp mount includes noexec,nosuid.")
        checks.append(_check("tmp-mount-hardening", "pass", "/tmp mount includes both noexec and nosuid."))
    else:
        missing = []
        if not has_noexec:
            missing.append("noexec")
        if not has_nosuid:
            missing.append("nosuid")
        message = f"/tmp mount missing options: {', '.join(missing)}."
        logger.warn(message)
        checks.append(
            _check(
                "tmp-mount-hardening",
                "warn",
                message,
                fix="Update /etc/fstab to include noexec,nosuid for /tmp and remount.",
            )
        )

    return {"name": "filesystem", "checks": checks}
