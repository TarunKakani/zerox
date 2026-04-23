import re
import shutil
import subprocess
from typing import Dict, List, Set


def _check(check_id: str, status: str, message: str, fix: str = None, details: str = None) -> Dict[str, str]:
    item = {"id": check_id, "status": status, "message": message}
    if fix:
        item["fix"] = fix
    if details:
        item["details"] = details
    return item


def _listening_ports() -> Set[int]:
    ports: Set[int] = set()
    if not shutil.which("ss"):
        return ports
    proc = subprocess.run(["ss", "-H", "-tuln"], capture_output=True, text=True)
    if proc.returncode not in (0, 1):
        return ports
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        local_addr = parts[4]
        match = re.search(r":(\d+)$", local_addr)
        if not match:
            continue
        try:
            ports.add(int(match.group(1)))
        except ValueError:
            continue
    return ports


def _running_services() -> Set[str]:
    if not shutil.which("systemctl"):
        return set()
    command = ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"]
    proc = subprocess.run(command, capture_output=True, text=True)
    if proc.returncode != 0:
        return set()
    return {line.split()[0] for line in proc.stdout.splitlines() if line.strip()}


def _normalize_expected_service(name: str) -> Set[str]:
    normalized = name.strip()
    if not normalized:
        return set()
    values = {normalized}
    if "." not in normalized:
        values.add(f"{normalized}.service")
    return values


def run_scan(logger, policy: Dict[str, object] = None, **_: Dict[str, object]) -> Dict[str, List[Dict[str, str]]]:
    checks: List[Dict[str, str]] = []
    policy = policy or {}
    expected_ports_raw = policy.get("expected_ports")
    expected_services_raw = policy.get("expected_services")

    if expected_ports_raw is None and expected_services_raw is None:
        logger.warn("Expected-surface policy is not configured (expected_ports/expected_services missing).")
        checks.append(
            _check(
                "surface-policy-missing",
                "warn",
                "Policy does not define expected_ports or expected_services.",
                fix="Add expected ports/services to the policy file.",
            )
        )
        return {"name": "surface", "checks": checks}

    if expected_ports_raw is not None:
        expected_ports = {int(item) for item in expected_ports_raw}
        observed_ports = _listening_ports()
        unexpected_ports = sorted(port for port in observed_ports if port not in expected_ports)
        if unexpected_ports:
            logger.fail(f"Unexpected listening ports detected: {', '.join(str(p) for p in unexpected_ports[:20])}.")
            checks.append(
                _check(
                    "surface-ports",
                    "fail",
                    f"Unexpected listening ports found: {', '.join(str(p) for p in unexpected_ports[:20])}.",
                    details=f"Observed={sorted(observed_ports)} Expected={sorted(expected_ports)}",
                    fix="Update service exposure or policy allowlist.",
                )
            )
        else:
            logger.passed("Listening ports match expected allowlist.")
            checks.append(
                _check(
                    "surface-ports",
                    "pass",
                    "Listening ports match expected allowlist.",
                    details=f"Observed={sorted(observed_ports)}",
                )
            )

    if expected_services_raw is not None:
        expected_services: Set[str] = set()
        for item in expected_services_raw:
            expected_services.update(_normalize_expected_service(str(item)))
        observed_services = _running_services()
        if not observed_services and shutil.which("systemctl"):
            logger.warn("Unable to enumerate running services for allowlist comparison.")
            checks.append(_check("surface-services-enumeration", "warn", "Could not enumerate running services."))
        else:
            unexpected_services = sorted(service for service in observed_services if service not in expected_services)
            if unexpected_services:
                logger.fail(f"Unexpected running services detected: {', '.join(unexpected_services[:15])}.")
                checks.append(
                    _check(
                        "surface-services",
                        "fail",
                        f"Unexpected running services found: {', '.join(unexpected_services[:15])}.",
                        details=f"Observed={sorted(observed_services)[:30]}",
                        fix="Stop/disable unexpected services or update policy allowlist.",
                    )
                )
            else:
                logger.passed("Running services match expected allowlist.")
                checks.append(_check("surface-services", "pass", "Running services match expected allowlist."))

    return {"name": "surface", "checks": checks}
