import re
import shutil
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple


WEAK_SIGNATURE_TOKENS = ("md5", "sha1")


def _check(check_id: str, status: str, message: str, fix: str = None, details: str = None) -> Dict[str, str]:
    item = {"id": check_id, "status": status, "message": message}
    if fix:
        item["fix"] = fix
    if details:
        item["details"] = details
    return item


def _parse_target(raw: str) -> Tuple[str, int]:
    host, _, port = raw.partition(":")
    if not host:
        return "", 0
    if not port:
        return host, 443
    return host, int(port)


def _discover_local_tls_targets() -> Set[str]:
    targets: Set[str] = set()
    if not shutil.which("ss"):
        return targets
    proc = subprocess.run(["ss", "-H", "-tuln"], capture_output=True, text=True)
    if proc.returncode not in (0, 1):
        return targets
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        match = re.search(r":(\d+)$", parts[4])
        if not match:
            continue
        port = int(match.group(1))
        if port in {443, 8443, 9443}:
            targets.add(f"127.0.0.1:{port}")
    return targets


def _cert_days_remaining(host: str, port: int) -> Tuple[int, str]:
    context = ssl._create_unverified_context()
    with socket.create_connection((host, port), timeout=4) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            cert = tls_sock.getpeercert()
    if "notAfter" not in cert:
        raise ValueError("Certificate did not include notAfter field.")
    expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return (expiry - now).days, expiry.isoformat()


def _signature_algorithm(host: str, port: int) -> str:
    if not shutil.which("openssl"):
        return ""
    try:
        s_client = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host],
            input="",
            capture_output=True,
            text=True,
            timeout=8,
        )
    except subprocess.TimeoutExpired:
        return ""
    if s_client.returncode != 0 or not s_client.stdout:
        return ""
    x509 = subprocess.run(
        ["openssl", "x509", "-noout", "-text"],
        input=s_client.stdout,
        capture_output=True,
        text=True,
    )
    if x509.returncode != 0:
        return ""
    for line in x509.stdout.splitlines():
        marker = "Signature Algorithm:"
        if marker in line:
            return line.split(marker, 1)[1].strip().lower()
    return ""


def run_scan(logger, policy: Dict[str, object] = None, **_: Dict[str, object]) -> Dict[str, List[Dict[str, str]]]:
    checks: List[Dict[str, str]] = []
    policy = policy or {}
    targets: Set[str] = set(_discover_local_tls_targets())

    policy_targets = policy.get("tls_targets", [])
    if isinstance(policy_targets, list):
        for item in policy_targets:
            if isinstance(item, str) and item.strip():
                targets.add(item.strip())

    if not targets:
        logger.info("No TLS targets discovered or configured.")
        checks.append(
            _check(
                "tls-targets",
                "skip",
                "No TLS targets discovered/configured. Add policy.tls_targets to enable remote checks.",
            )
        )
        return {"name": "tls", "checks": checks}

    checks.append(_check("tls-targets", "info", f"Evaluating {len(targets)} TLS target(s)."))
    for raw_target in sorted(targets):
        try:
            host, port = _parse_target(raw_target)
        except ValueError:
            checks.append(_check(f"tls-{raw_target}", "error", f"Invalid TLS target format: {raw_target}."))
            continue
        if not host or port <= 0:
            checks.append(_check(f"tls-{raw_target}", "error", f"Invalid TLS target: {raw_target}."))
            continue

        check_id = f"tls-{host}-{port}"
        try:
            days_remaining, expiry = _cert_days_remaining(host, port)
        except (OSError, ssl.SSLError, ValueError) as exc:
            logger.warn(f"TLS check failed for {host}:{port}: {exc}")
            checks.append(_check(check_id, "warn", f"Could not evaluate TLS certificate for {host}:{port}.", details=str(exc)))
            continue

        if days_remaining < 0:
            logger.fail(f"Certificate expired for {host}:{port} ({expiry}).")
            checks.append(
                _check(
                    check_id,
                    "fail",
                    f"TLS certificate expired for {host}:{port}.",
                    details=f"Expiry={expiry}",
                    fix="Rotate certificate immediately.",
                )
            )
        elif days_remaining <= 30:
            logger.warn(f"Certificate for {host}:{port} expires in {days_remaining} day(s).")
            checks.append(
                _check(
                    check_id,
                    "warn",
                    f"TLS certificate expires soon for {host}:{port} ({days_remaining} days).",
                    details=f"Expiry={expiry}",
                    fix="Plan certificate renewal before expiry.",
                )
            )
        else:
            checks.append(_check(check_id, "pass", f"TLS certificate valid for {host}:{port} ({days_remaining} days remaining)."))

        algorithm = _signature_algorithm(host, port)
        if not algorithm:
            checks.append(_check(f"{check_id}-sigalg", "skip", f"Could not determine signature algorithm for {host}:{port}."))
            continue
        if any(token in algorithm for token in WEAK_SIGNATURE_TOKENS):
            logger.fail(f"Weak certificate signature algorithm for {host}:{port}: {algorithm}.")
            checks.append(
                _check(
                    f"{check_id}-sigalg",
                    "fail",
                    f"Weak TLS certificate signature algorithm on {host}:{port}: {algorithm}.",
                    fix="Reissue certificate using SHA-256 or stronger signature algorithm.",
                )
            )
        else:
            checks.append(_check(f"{check_id}-sigalg", "pass", f"Strong TLS signature algorithm detected on {host}:{port}: {algorithm}."))

    return {"name": "tls", "checks": checks}
