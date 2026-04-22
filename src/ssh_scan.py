import os
import re
import shutil
import subprocess
from typing import Dict, List


SECURE_DIRECTIVES = {
    "PasswordAuthentication": {
        "expected": "no",
        "cis": "CIS Benchmark 5.2.4",
    },
    "PermitRootLogin": {
        "expected": "no",
        "cis": "CIS Benchmark 5.2.8",
    },
    "PermitEmptyPasswords": {
        "expected": "no",
        "cis": "CIS Benchmark 5.2.9",
    },
}


def _check(check_id: str, status: str, message: str, cis: str = None, fix: str = None, details: str = None) -> Dict[str, str]:
    item = {"id": check_id, "status": status, "message": message}
    if cis:
        item["cis"] = cis
    if fix:
        item["fix"] = fix
    if details:
        item["details"] = details
    return item


def _parse_ssh_config(filepath: str) -> Dict[str, str]:
    values = {}
    if not os.path.exists(filepath):
        return values
    with open(filepath, "r", encoding="utf-8", errors="ignore") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            key = parts[0]
            value = parts[1]
            if key in SECURE_DIRECTIVES:
                values[key] = value
    return values


def _set_directive(filepath: str, key: str, value: str) -> bool:
    if not os.path.exists(filepath):
        return False
    with open(filepath, "r", encoding="utf-8", errors="ignore") as handle:
        lines = handle.readlines()

    pattern = re.compile(rf"^\s*{re.escape(key)}\b", re.IGNORECASE)
    replaced = False
    updated_lines: List[str] = []
    for line in lines:
        if not line.lstrip().startswith("#") and pattern.match(line):
            updated_lines.append(f"{key} {value}\n")
            replaced = True
        else:
            updated_lines.append(line)
    if not replaced:
        if updated_lines and not updated_lines[-1].endswith("\n"):
            updated_lines[-1] = f"{updated_lines[-1]}\n"
        updated_lines.append(f"{key} {value}\n")

    backup_path = f"{filepath}.bak"
    if not os.path.exists(backup_path):
        shutil.copy2(filepath, backup_path)
    with open(filepath, "w", encoding="utf-8") as handle:
        handle.writelines(updated_lines)
    return True


def _detect_ssh_service() -> str:
    for service in ("sshd", "ssh"):
        proc = subprocess.run(["systemctl", "is-active", service], capture_output=True, text=True)
        if proc.returncode in (0, 3):
            return service
        if proc.returncode == 4:
            continue
    return ""


def run_scan(logger, fix: bool = False, **_: Dict[str, str]) -> Dict[str, List[Dict[str, str]]]:
    checks: List[Dict[str, str]] = []

    if not shutil.which("systemctl"):
        message = "systemd not detected. Skipping service checks."
        logger.skip(f"[*] {message}")
        checks.append(_check("ssh-systemd", "skip", message))
    else:
        service = _detect_ssh_service()
        if not service:
            message = "SSH service unit not found (checked sshd/ssh)."
            logger.fail(message)
            checks.append(_check("ssh-service", "fail", message))
        else:
            active = subprocess.run(["systemctl", "is-active", service], capture_output=True, text=True).stdout.strip()
            enabled = subprocess.run(["systemctl", "is-enabled", service], capture_output=True, text=True).stdout.strip()
            if active == "active":
                logger.passed(f"SSH service '{service}' is active and '{enabled}' on boot.")
                checks.append(_check("ssh-service-state", "pass", f"SSH service '{service}' active; boot state: {enabled}."))
            else:
                message = f"SSH service '{service}' is not active (state: {active})."
                logger.warn(message)
                checks.append(_check("ssh-service-state", "warn", message))

    sshd_file = "/etc/ssh/sshd_config"
    client_file = "/etc/ssh/ssh_config"
    sshd_values = _parse_ssh_config(sshd_file)
    client_values = _parse_ssh_config(client_file)

    for directive, meta in SECURE_DIRECTIVES.items():
        expected = meta["expected"]
        cis = meta["cis"]
        actual = sshd_values.get(directive, "Not Found")
        if actual == "Not Found":
            message = f"{directive} is not explicitly set in {sshd_file}."
            logger.warn(message)
            checks.append(
                _check(
                    f"sshd-{directive.lower()}",
                    "warn",
                    message,
                    cis=cis,
                    fix=f"Add '{directive} {expected}' to {sshd_file}.",
                )
            )
            if fix:
                try:
                    if _set_directive(sshd_file, directive, expected):
                        logger.fixed(f"Applied fix: {directive} {expected} in {sshd_file}.")
                        checks.append(
                            _check(
                                f"sshd-{directive.lower()}-fixed",
                                "fixed",
                                f"Set {directive} to {expected} in {sshd_file}.",
                                cis=cis,
                            )
                        )
                except PermissionError:
                    logger.error(f"Permission denied while editing {sshd_file}.")
                    checks.append(_check(f"sshd-{directive.lower()}-fix-error", "error", f"Permission denied editing {sshd_file}."))
            continue

        if actual.lower() != expected:
            message = f"{directive} is '{actual}' (expected '{expected}') ({cis})."
            logger.fail(message)
            checks.append(
                _check(
                    f"sshd-{directive.lower()}",
                    "fail",
                    message,
                    cis=cis,
                    fix=f"Set '{directive} {expected}' in {sshd_file}, then restart SSH service.",
                )
            )
            if fix:
                try:
                    if _set_directive(sshd_file, directive, expected):
                        logger.fixed(f"Applied fix: {directive} {expected} in {sshd_file}.")
                        checks.append(
                            _check(
                                f"sshd-{directive.lower()}-fixed",
                                "fixed",
                                f"Set {directive} to {expected} in {sshd_file}.",
                                cis=cis,
                            )
                        )
                except PermissionError:
                    logger.error(f"Permission denied while editing {sshd_file}.")
                    checks.append(_check(f"sshd-{directive.lower()}-fix-error", "error", f"Permission denied editing {sshd_file}."))
        else:
            logger.passed(f"{directive} is securely set to '{actual}' ({cis}).")
            checks.append(_check(f"sshd-{directive.lower()}", "pass", f"{directive} is securely set to '{actual}'.", cis=cis))

    if client_values:
        logger.info(f"Read SSH client config from {client_file}.")
        checks.append(_check("ssh-client-config", "info", f"SSH client config parsed from {client_file}."))
    else:
        logger.skip(f"{client_file} not found or has no explicit SSH directives.")
        checks.append(_check("ssh-client-config", "skip", f"{client_file} not found or no directives were set."))

    return {"name": "ssh", "checks": checks}
