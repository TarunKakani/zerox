import shutil
import subprocess
from typing import Dict, List


def _check(check_id: str, status: str, message: str, cis: str = None, fix: str = None, details: str = None) -> Dict[str, str]:
    item = {"id": check_id, "status": status, "message": message}
    if cis:
        item["cis"] = cis
    if fix:
        item["fix"] = fix
    if details:
        item["details"] = details
    return item


def _set_sysctl(logger, key: str, value: str) -> bool:
    proc = subprocess.run(["sysctl", "-w", f"{key}={value}"], capture_output=True, text=True)
    if proc.returncode == 0:
        logger.fixed(f"Applied sysctl {key}={value}.")
        return True
    logger.error(f"Failed to apply sysctl {key}={value}: {proc.stderr.strip()}")
    return False


def _scan_ports(logger) -> Dict[str, str]:
    if not shutil.which("ss"):
        logger.error("'ss' command not found. Cannot perform listening port scan.")
        return _check("open-ports", "error", "'ss' command not found.")

    proc = subprocess.run(["ss", "-tuln"], capture_output=True, text=True)
    if proc.returncode not in (0, 1):
        msg = proc.stderr.strip() or "ss command failed."
        logger.error(f"Port scan failed: {msg}")
        return _check("open-ports", "error", f"Port scan failed: {msg}")

    lines = proc.stdout.strip().splitlines()[1:]
    summary = f"Found {len(lines)} listening sockets."
    logger.info(summary)
    details = "; ".join(lines[:25]) if lines else None
    return _check("open-ports", "info", summary, details=details)


def _scan_firewall(logger) -> Dict[str, str]:
    if shutil.which("ufw"):
        ufw = subprocess.run(["ufw", "status", "verbose"], capture_output=True, text=True)
        if ufw.returncode == 0:
            if "Status: active" in ufw.stdout:
                logger.passed("UFW firewall is active.")
                return _check("firewall", "pass", "UFW firewall is active.")
            logger.fail("UFW is installed but inactive.")
            return _check("firewall", "fail", "UFW is installed but inactive.", fix="Run: ufw enable")

    if shutil.which("firewall-cmd"):
        fw = subprocess.run(["firewall-cmd", "--state"], capture_output=True, text=True)
        if fw.returncode == 0 and fw.stdout.strip() == "running":
            logger.passed("Firewalld is running.")
            return _check("firewall", "pass", "Firewalld is active.")
        logger.fail("Firewalld is installed but not running.")
        return _check("firewall", "fail", "Firewalld is installed but inactive.")

    if shutil.which("nft"):
        nft = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True)
        if nft.returncode == 0 and nft.stdout.strip():
            logger.passed("nftables ruleset detected.")
            return _check("firewall", "pass", "nftables ruleset detected.")

    if shutil.which("iptables"):
        ipt = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True)
        if ipt.returncode == 0:
            logger.warn("Using legacy iptables rules.")
            return _check("firewall", "warn", "iptables rules detected. Verify default DROP/REJECT policies.")

    logger.fail("No active firewall detected (UFW/Firewalld/nftables/iptables).")
    return _check(
        "firewall",
        "fail",
        "No active firewall detected.",
        cis="CIS Benchmark 3.5.x",
        fix="Enable one host firewall stack and define default deny policies.",
    )


def run_scan(logger, fix: bool = False, **_: Dict[str, str]) -> Dict[str, List[Dict[str, str]]]:
    checks: List[Dict[str, str]] = []
    checks.append(_scan_ports(logger))
    checks.append(_scan_firewall(logger))

    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r", encoding="utf-8", errors="ignore") as handle:
            ip_forward = handle.read().strip()
        if ip_forward == "0":
            logger.passed("IPv4 forwarding is disabled.")
            checks.append(_check("ip-forward", "pass", "IPv4 forwarding is disabled."))
        else:
            message = "IPv4 forwarding is enabled; disable unless this host is acting as a router."
            logger.warn(message)
            checks.append(
                _check(
                    "ip-forward",
                    "warn",
                    message,
                    cis="CIS Benchmark 3.1.1",
                    fix="Run: sysctl -w net.ipv4.ip_forward=0",
                )
            )
            if fix and _set_sysctl(logger, "net.ipv4.ip_forward", "0"):
                checks.append(_check("ip-forward-fixed", "fixed", "Set net.ipv4.ip_forward=0."))
    except FileNotFoundError:
        logger.error("Could not read /proc/sys/net/ipv4/ip_forward.")
        checks.append(_check("ip-forward", "error", "Could not read /proc/sys/net/ipv4/ip_forward."))

    try:
        with open("/proc/sys/net/ipv4/icmp_echo_ignore_all", "r", encoding="utf-8", errors="ignore") as handle:
            ping_mode = handle.read().strip()
        if ping_mode == "1":
            logger.passed("ICMP echo requests are ignored.")
            checks.append(_check("icmp-echo", "pass", "Host ignores ICMP echo requests."))
        else:
            message = "Host responds to ICMP echo requests."
            logger.warn(message)
            checks.append(
                _check(
                    "icmp-echo",
                    "warn",
                    message,
                    fix="Run: sysctl -w net.ipv4.icmp_echo_ignore_all=1 (if stealth mode is desired).",
                )
            )
            if fix and _set_sysctl(logger, "net.ipv4.icmp_echo_ignore_all", "1"):
                checks.append(_check("icmp-echo-fixed", "fixed", "Set net.ipv4.icmp_echo_ignore_all=1."))
    except FileNotFoundError:
        logger.error("Could not read /proc/sys/net/ipv4/icmp_echo_ignore_all.")
        checks.append(_check("icmp-echo", "error", "Could not read /proc/sys/net/ipv4/icmp_echo_ignore_all."))

    return {"name": "network", "checks": checks}
