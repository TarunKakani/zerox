import shutil
import subprocess
from typing import Dict, List, Set


RISKY_SERVICES = {
    "cups.service",
    "avahi-daemon.service",
    "telnet.socket",
    "vsftpd.service",
    "rpcbind.service",
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


def _service_name_variants(exclusions: Set[str]) -> Set[str]:
    variants = set()
    for item in exclusions:
        normalized = item.strip()
        if not normalized:
            continue
        variants.add(normalized)
        if "." not in normalized:
            variants.add(f"{normalized}.service")
            variants.add(f"{normalized}.socket")
    return variants


def _scan_risky_services(logger, fix: bool, exclusions: Set[str]) -> List[Dict[str, str]]:
    checks: List[Dict[str, str]] = []
    if not shutil.which("systemctl"):
        message = "systemd not detected. Skipping service checks."
        logger.skip(f"[*] {message}")
        checks.append(_check("services-systemd", "skip", message))
        return checks

    command = ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"]
    proc = subprocess.run(command, capture_output=True, text=True)
    if proc.returncode != 0:
        stderr = proc.stderr.strip() or "systemctl list-units failed."
        logger.error(f"Failed to enumerate running services: {stderr}")
        checks.append(_check("services-enumeration", "error", f"Failed to enumerate running services: {stderr}"))
        return checks

    running_services = {line.split()[0] for line in proc.stdout.splitlines() if line.strip()}
    excluded = _service_name_variants(exclusions)
    risky_found = sorted((RISKY_SERVICES - excluded).intersection(running_services))

    if risky_found:
        for service in risky_found:
            message = f"Known risky/unnecessary service is running: {service}."
            logger.fail(message)
            checks.append(
                _check(
                    f"service-{service}",
                    "fail",
                    message,
                    cis="CIS Benchmark 2.1.x",
                    fix=f"Run: systemctl disable --now {service}",
                )
            )
            if fix:
                disable_proc = subprocess.run(["systemctl", "disable", "--now", service], capture_output=True, text=True)
                if disable_proc.returncode == 0:
                    logger.fixed(f"Disabled and stopped {service}.")
                    checks.append(_check(f"service-{service}-fixed", "fixed", f"Disabled and stopped {service}."))
                else:
                    logger.error(f"Failed to disable {service}: {disable_proc.stderr.strip()}")
                    checks.append(_check(f"service-{service}-fix-error", "error", f"Failed to disable {service}."))
    else:
        logger.passed("No known risky services detected as running.")
        checks.append(_check("risky-services", "pass", "No known risky services are running."))
    return checks


def _scan_updates(logger) -> Dict[str, str]:
    if shutil.which("apt"):
        proc = subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True)
        lines = [line for line in proc.stdout.splitlines() if "/" in line]
        if lines:
            logger.warn(f"{len(lines)} package updates available via APT.")
            return _check("updates", "warn", f"{len(lines)} package updates available via APT.", fix="Run: apt update && apt upgrade")
        logger.passed("APT reports no upgradable packages.")
        return _check("updates", "pass", "APT reports no upgradable packages.")

    for pm in ("dnf", "yum"):
        if shutil.which(pm):
            proc = subprocess.run([pm, "check-update"], capture_output=True, text=True)
            if proc.returncode == 100:
                logger.warn(f"Package updates available via {pm}.")
                return _check("updates", "warn", f"Package updates available via {pm}.", fix=f"Run: {pm} upgrade")
            if proc.returncode == 0:
                logger.passed(f"{pm} reports no updates.")
                return _check("updates", "pass", f"{pm} reports no updates.")
            logger.error(f"{pm} returned exit code {proc.returncode}.")
            return _check("updates", "error", f"{pm} returned exit code {proc.returncode}.")

    if shutil.which("pacman"):
        proc = subprocess.run(["pacman", "-Qu"], capture_output=True, text=True)
        lines = proc.stdout.strip().splitlines() if proc.stdout.strip() else []
        if lines:
            logger.warn(f"{len(lines)} package updates available via pacman.")
            return _check("updates", "warn", f"{len(lines)} package updates available via pacman.", fix="Run: pacman -Syu")
        logger.passed("Pacman reports no updates.")
        return _check("updates", "pass", "Pacman reports no updates.")

    logger.warn("No supported package manager found for update checks.")
    return _check("updates", "warn", "No supported package manager found for update checks.")


def run_scan(logger, fix: bool = False, exclude_services: List[str] = None, **_: Dict[str, str]) -> Dict[str, List[Dict[str, str]]]:
    excluded_set = set(exclude_services or [])
    checks = _scan_risky_services(logger, fix=fix, exclusions=excluded_set)
    checks.append(_scan_updates(logger))
    return {"name": "services", "checks": checks}
