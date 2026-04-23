import glob
import os
from typing import Dict, List, Set


DEFAULT_HIGH_RISK_MODULES = {
    "cramfs",
    "dccp",
    "freevxfs",
    "hfs",
    "hfsplus",
    "jffs2",
    "rds",
    "sctp",
    "squashfs",
    "tipc",
    "udf",
    "usb_storage",
}


def _check(check_id: str, status: str, message: str, fix: str = None, details: str = None) -> Dict[str, str]:
    item = {"id": check_id, "status": status, "message": message}
    if fix:
        item["fix"] = fix
    if details:
        item["details"] = details
    return item


def _loaded_modules() -> Set[str]:
    loaded: Set[str] = set()
    with open("/proc/modules", "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            parts = line.split()
            if parts:
                loaded.add(parts[0])
    return loaded


def _blocked_modules() -> Set[str]:
    blocked: Set[str] = set()
    for path in sorted(glob.glob("/etc/modprobe.d/*.conf")):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("blacklist "):
                        blocked.add(line.split()[1])
                    if line.startswith("install ") and "/bin/true" in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            blocked.add(parts[1])
        except PermissionError:
            continue
    return blocked


def _write_deny_rules(path: str, modules: List[str]) -> None:
    existing = ""
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            existing = handle.read()
    additions: List[str] = []
    for module in modules:
        blacklist_line = f"blacklist {module}"
        install_line = f"install {module} /bin/true"
        if blacklist_line not in existing:
            additions.append(blacklist_line)
        if install_line not in existing:
            additions.append(install_line)
    if not additions:
        return
    with open(path, "a", encoding="utf-8") as handle:
        for line in additions:
            handle.write(f"{line}\n")


def run_scan(logger, fix: bool = False, policy: Dict[str, object] = None, **_: Dict[str, object]) -> Dict[str, List[Dict[str, str]]]:
    checks: List[Dict[str, str]] = []
    policy = policy or {}

    high_risk_modules = set(DEFAULT_HIGH_RISK_MODULES)
    configured = policy.get("high_risk_modules")
    if isinstance(configured, list):
        high_risk_modules.update(str(item).strip() for item in configured if str(item).strip())

    try:
        loaded = _loaded_modules()
    except FileNotFoundError:
        logger.error("/proc/modules not available on this host.")
        checks.append(_check("modules-source", "error", "/proc/modules not available."))
        return {"name": "modules", "checks": checks}

    risky_loaded = sorted(module for module in loaded if module in high_risk_modules)
    blocked = _blocked_modules()
    blocked_coverage = sorted(module for module in high_risk_modules if module in blocked)

    if risky_loaded:
        logger.warn(f"Loaded high-risk modules detected: {', '.join(risky_loaded)}.")
        checks.append(
            _check(
                "modules-loaded-risky",
                "warn",
                f"Loaded high-risk modules detected: {', '.join(risky_loaded)}.",
                fix="Unload unneeded modules and deny-load them via /etc/modprobe.d/*.conf.",
            )
        )
        if fix:
            deny_path = "/etc/modprobe.d/zerox-deny.conf"
            try:
                _write_deny_rules(deny_path, risky_loaded)
                logger.fixed(f"Wrote deny rules for {len(risky_loaded)} module(s) to {deny_path}.")
                checks.append(
                    _check(
                        "modules-deny-rules",
                        "fixed",
                        f"Wrote deny rules for {len(risky_loaded)} module(s) to {deny_path}.",
                    )
                )
            except PermissionError:
                logger.error(f"Permission denied writing {deny_path}.")
                checks.append(_check("modules-deny-rules", "error", f"Permission denied writing {deny_path}."))
    else:
        logger.passed("No configured high-risk modules are currently loaded.")
        checks.append(_check("modules-loaded-risky", "pass", "No configured high-risk modules are currently loaded."))

    if blocked_coverage:
        checks.append(
            _check(
                "modules-blocked-coverage",
                "pass",
                f"{len(blocked_coverage)} high-risk module(s) already blocked in modprobe policy.",
                details="; ".join(blocked_coverage[:25]),
            )
        )
    else:
        checks.append(
            _check(
                "modules-blocked-coverage",
                "warn",
                "No high-risk module deny rules were found in /etc/modprobe.d.",
                fix="Create modprobe deny rules for modules not needed on this host.",
            )
        )

    return {"name": "modules", "checks": checks}
