import os
import platform
import subprocess
from typing import Dict, List


KERNEL_PARAMS = {
    "kernel.randomize_va_space": {
        "path": "/proc/sys/kernel/randomize_va_space",
        "expected": "2",
        "cis": "CIS Benchmark 1.5.x",
    },
    "fs.suid_dumpable": {
        "path": "/proc/sys/fs/suid_dumpable",
        "expected": "0",
        "cis": "CIS Benchmark 1.5.x",
    },
    "net.ipv4.conf.all.rp_filter": {
        "path": "/proc/sys/net/ipv4/conf/all/rp_filter",
        "expected": "1",
        "cis": "CIS Benchmark 3.3.x",
    },
}


def _check(check_id: str, status: str, message: str, cis: str = None, fix: str = None) -> Dict[str, str]:
    item = {"id": check_id, "status": status, "message": message}
    if cis:
        item["cis"] = cis
    if fix:
        item["fix"] = fix
    return item


def _set_sysctl(logger, key: str, value: str) -> bool:
    proc = subprocess.run(["sysctl", "-w", f"{key}={value}"], capture_output=True, text=True)
    if proc.returncode == 0:
        logger.fixed(f"Applied sysctl {key}={value}.")
        return True
    logger.error(f"Failed to apply sysctl {key}={value}: {proc.stderr.strip()}")
    return False


def run_scan(logger, fix: bool = False, **_: Dict[str, str]) -> Dict[str, List[Dict[str, str]]]:
    checks: List[Dict[str, str]] = []

    kernel_version = platform.release()
    logger.info(f"Detected Linux kernel version: {kernel_version}")
    checks.append(_check("kernel-version", "info", f"Detected kernel version: {kernel_version}."))

    for key, config in KERNEL_PARAMS.items():
        try:
            with open(config["path"], "r", encoding="utf-8", errors="ignore") as handle:
                actual = handle.read().strip()
        except FileNotFoundError:
            message = f"Kernel parameter path not found: {config['path']}."
            logger.error(message)
            checks.append(_check(f"sysctl-{key}", "error", message))
            continue

        expected = config["expected"]
        cis = config["cis"]
        if actual == expected:
            logger.passed(f"{key} is securely set to {actual} ({cis}).")
            checks.append(_check(f"sysctl-{key}", "pass", f"{key} is securely set to {actual}.", cis=cis))
        else:
            message = f"{key} is {actual} (expected {expected}) ({cis})."
            logger.fail(message)
            checks.append(
                _check(
                    f"sysctl-{key}",
                    "fail",
                    message,
                    cis=cis,
                    fix=f"Run: sysctl -w {key}={expected}",
                )
            )
            if fix and _set_sysctl(logger, key, expected):
                checks.append(_check(f"sysctl-{key}-fixed", "fixed", f"Set {key}={expected}.", cis=cis))

    try:
        with open("/proc/sys/net/ipv6/conf/all/disable_ipv6", "r", encoding="utf-8", errors="ignore") as handle:
            ipv6_status = handle.read().strip()
        if ipv6_status == "1":
            logger.passed("IPv6 is disabled.")
            checks.append(_check("ipv6-status", "pass", "IPv6 is disabled."))
        else:
            logger.warn("IPv6 is enabled. If unused, disable it to reduce attack surface.")
            checks.append(
                _check(
                    "ipv6-status",
                    "warn",
                    "IPv6 is enabled. If unused, consider disabling it.",
                    fix="If IPv6 is not needed, set net.ipv6.conf.all.disable_ipv6=1.",
                )
            )
    except FileNotFoundError:
        logger.info("IPv6 stack not detected on this system.")
        checks.append(_check("ipv6-status", "info", "IPv6 stack not detected."))

    grub_paths = ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"]
    found = False
    for path in grub_paths:
        if not os.path.exists(path):
            continue
        found = True
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                grub_cfg = handle.read()
            if "password_pbkdf2" in grub_cfg:
                logger.passed(f"GRUB bootloader is password-protected ({path}).")
                checks.append(_check("grub-password", "pass", f"GRUB menu password protection found in {path}."))
            else:
                logger.fail(f"GRUB menu lacks password protection in {path}.")
                checks.append(
                    _check(
                        "grub-password",
                        "fail",
                        f"No password protection found in {path}.",
                        cis="CIS Benchmark 1.4.1",
                        fix="Configure a GRUB superuser with password_pbkdf2.",
                    )
                )
        except PermissionError:
            logger.error(f"Permission denied reading {path}.")
            checks.append(_check("grub-password", "error", f"Permission denied reading {path}."))
        break

    if not found:
        logger.warn("Could not locate standard GRUB config; system may use another bootloader.")
        checks.append(_check("grub-password", "warn", "Standard GRUB config not found."))

    return {"name": "kernel", "checks": checks}
