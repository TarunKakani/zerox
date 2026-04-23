import grp
import pwd
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


def _scan_shadow_for_empty_hashes() -> List[str]:
    empty_hash_users: List[str] = []
    with open("/etc/shadow", "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            row = line.strip()
            if not row:
                continue
            parts = row.split(":")
            if len(parts) < 2:
                continue
            user, hash_field = parts[0], parts[1]
            if hash_field == "":
                empty_hash_users.append(user)
    return empty_hash_users


def _scan_orphan_users() -> List[Dict[str, int]]:
    valid_groups = {group.gr_gid for group in grp.getgrall()}
    orphan_users: List[Dict[str, int]] = []
    for user in pwd.getpwall():
        if user.pw_gid not in valid_groups:
            orphan_users.append({"user": user.pw_name, "invalid_gid": user.pw_gid})
    return orphan_users


def _scan_rogue_uid_zero_users() -> List[str]:
    return [user.pw_name for user in pwd.getpwall() if user.pw_uid == 0 and user.pw_name != "root"]


def _pam_line_exists(filepaths: List[str], needle: str) -> bool:
    for path in filepaths:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    candidate = line.strip()
                    if not candidate or candidate.startswith("#"):
                        continue
                    if needle in candidate:
                        return True
        except FileNotFoundError:
            continue
    return False


def run_scan(logger, fix: bool = False, **_: Dict[str, str]) -> Dict[str, List[Dict[str, str]]]:
    del fix
    checks: List[Dict[str, str]] = []

    try:
        empty_hash_users = _scan_shadow_for_empty_hashes()
        if empty_hash_users:
            message = f"Accounts with empty password hashes found: {', '.join(empty_hash_users)}."
            logger.fail(message)
            checks.append(
                _check(
                    "users-empty-hash",
                    "fail",
                    message,
                    cis="CIS Benchmark 5.4.x",
                    fix="Lock or remove these accounts and enforce password policy.",
                )
            )
        else:
            logger.passed("No accounts with empty password hashes in /etc/shadow.")
            checks.append(_check("users-empty-hash", "pass", "No empty password hashes found."))
    except PermissionError:
        logger.error("Permission denied reading /etc/shadow. Run as root for full IAM checks.")
        checks.append(_check("users-empty-hash", "error", "Permission denied reading /etc/shadow."))
    except FileNotFoundError:
        logger.error("/etc/shadow not found on this system.")
        checks.append(_check("users-empty-hash", "error", "/etc/shadow not found."))

    orphan_users = _scan_orphan_users()
    if orphan_users:
        names = ", ".join(f"{entry['user']}(gid={entry['invalid_gid']})" for entry in orphan_users[:10])
        message = f"Users with invalid primary group detected: {names}."
        logger.fail(message)
        checks.append(
            _check(
                "users-orphan-group",
                "fail",
                message,
                fix="Create missing groups or update each user primary group.",
            )
        )
    else:
        logger.passed("No orphan users with missing primary groups.")
        checks.append(_check("users-orphan-group", "pass", "No users with invalid primary group IDs found."))

    rogue_uid_zero = _scan_rogue_uid_zero_users()
    if rogue_uid_zero:
        message = f"Non-root UID 0 accounts detected: {', '.join(rogue_uid_zero)}."
        logger.fail(message)
        checks.append(
            _check(
                "users-uid-zero",
                "fail",
                message,
                cis="CIS Benchmark 5.4.2",
                fix="Remove UID 0 from non-root accounts or disable the accounts.",
            )
        )
    else:
        logger.passed("No rogue UID 0 user accounts found.")
        checks.append(_check("users-uid-zero", "pass", "Only root has UID 0."))

    pam_targets = ["/etc/pam.d/common-password", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]
    has_pwquality = _pam_line_exists(pam_targets, "pam_pwquality.so")
    has_lockout = _pam_line_exists(pam_targets, "pam_faillock.so") or _pam_line_exists(pam_targets, "pam_tally2.so")

    if has_pwquality:
        logger.passed("PAM password quality module is configured.")
        checks.append(_check("pam-pwquality", "pass", "Found pam_pwquality configuration."))
    else:
        logger.warn("PAM password quality module (pam_pwquality) was not found.")
        checks.append(
            _check(
                "pam-pwquality",
                "warn",
                "pam_pwquality not found in common PAM profiles.",
                fix="Configure pam_pwquality in PAM password stack.",
            )
        )

    if has_lockout:
        logger.passed("PAM account lockout policy appears configured.")
        checks.append(_check("pam-lockout", "pass", "Found faillock/tally configuration in PAM."))
    else:
        logger.warn("PAM lockout policy (pam_faillock/pam_tally2) was not found.")
        checks.append(
            _check(
                "pam-lockout",
                "warn",
                "No PAM lockout policy found in common PAM profiles.",
                fix="Configure pam_faillock to lock accounts after repeated failed logins.",
            )
        )

    return {"name": "identity", "checks": checks}
