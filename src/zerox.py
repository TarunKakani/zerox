#!/usr/bin/env python3
import argparse
import csv
import io
import json
import os
import platform
import shutil
import socket
from datetime import datetime, timezone
from typing import Dict, List

from modules.audit_logger import AuditLogger
import modules.auth_logs_scan as auth_logs_scan
import modules.baseline_scan as baseline_scan
import modules.file_perm_scan as file_perm_scan
import modules.kernel_modules_scan as kernel_modules_scan
import modules.kernel_scan as kernel_scan
import modules.network_scan as network_scan
import modules.persistence_scan as persistence_scan
import modules.scheduler_scan as scheduler_scan
import modules.services_scan as services_scan
import modules.ssh_scan as ssh_scan
import modules.sudoers_scan as sudoers_scan
import modules.surface_scan as surface_scan
import modules.tls_scan as tls_scan
import modules.user_management as user_management


SCAN_RUNNERS = {
    "authlogs": auth_logs_scan.run_scan,
    "baseline": baseline_scan.run_scan,
    "filesystem": file_perm_scan.run_scan,
    "ssh": ssh_scan.run_scan,
    "identity": user_management.run_scan,
    "kernel": kernel_scan.run_scan,
    "modules": kernel_modules_scan.run_scan,
    "network": network_scan.run_scan,
    "persistence": persistence_scan.run_scan,
    "scheduler": scheduler_scan.run_scan,
    "services": services_scan.run_scan,
    "sudoers": sudoers_scan.run_scan,
    "surface": surface_scan.run_scan,
    "tls": tls_scan.run_scan,
}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Zerox - server security auditing and hardening scanner")
    parser.add_argument("--quiet", action="store_true", help="Show only warnings/failures/errors in text output.")
    parser.add_argument("--full", action="store_true", help="Run the full scan suite.")
    parser.add_argument(
        "--scan",
        action="append",
        choices=sorted(SCAN_RUNNERS.keys()),
        help="Run specific scan(s). Can be specified multiple times.",
    )
    parser.add_argument(
        "--exclude-scan",
        action="append",
        choices=sorted(SCAN_RUNNERS.keys()),
        help="Exclude specific scan(s). Can be specified multiple times.",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Exclude service(s) from risky service checks. Can be specified multiple times.",
    )
    parser.add_argument("--format", choices=["text", "json", "csv"], default="text", help="Report output format.")
    parser.add_argument("--output", help="Path to save report output.")
    parser.add_argument("--policy", default="zerox_policy.json", help="Path to policy JSON (allowlists/rules).")
    parser.add_argument("--baseline-file", default="zerox_baseline.json", help="Path to baseline JSON file.")
    parser.add_argument("--init-baseline", action="store_true", help="Create/refresh baseline file from current system state.")
    parser.add_argument("--fix", action="store_true", help="Apply safe auto-fixes where supported.")
    parser.add_argument("--ssh-only", action="store_true", help="Run only SSH scan.")
    parser.add_argument("--identity-only", action="store_true", help="Run only identity/IAM scan.")
    parser.add_argument("--filesystem-only", action="store_true", help="Run only filesystem/permissions scan.")
    parser.add_argument("--network-only", action="store_true", help="Run only network scan.")
    parser.add_argument("--kernel-only", action="store_true", help="Run only kernel scan.")
    parser.add_argument("--services-only", action="store_true", help="Run only services/software scan.")
    return parser


def _collect_system_info(logger: AuditLogger) -> Dict[str, List[Dict[str, str]]]:
    checks: List[Dict[str, str]] = []
    hostname = socket.gethostname()
    os_name = platform.platform()
    kernel_version = platform.release()
    uid = os.geteuid() if hasattr(os, "geteuid") else -1

    logger.info("========== ZEROX SECURITY AUDIT ==========")
    logger.info(f"Host: {hostname}")
    logger.info(f"OS: {os_name}")
    logger.info(f"Kernel: {kernel_version}")
    logger.info(f"Effective UID: {uid}")

    checks.append({"id": "host", "status": "info", "message": f"Hostname: {hostname}"})
    checks.append({"id": "os", "status": "info", "message": f"OS: {os_name}"})
    checks.append({"id": "kernel", "status": "info", "message": f"Kernel: {kernel_version}"})
    checks.append({"id": "euid", "status": "info", "message": f"Effective UID: {uid}"})

    tools = ["systemctl", "ss", "ufw", "firewall-cmd", "iptables", "nft", "apt", "dnf", "yum", "pacman"]
    for tool in tools:
        installed = shutil.which(tool) is not None
        if installed:
            logger.passed(f"Tool available: {tool}")
        else:
            logger.skip(f"Tool missing: {tool}")
        checks.append(
            {
                "id": f"tool-{tool}",
                "status": "pass" if installed else "skip",
                "message": f"{tool} {'found' if installed else 'not found'}",
            }
        )
    return {"name": "system_info", "checks": checks}


def _summarize(scans: List[Dict[str, List[Dict[str, str]]]]) -> Dict[str, int]:
    summary = {status: 0 for status in ["pass", "warn", "fail", "error", "info", "skip", "fixed"]}
    for scan in scans:
        for check in scan["checks"]:
            status = check.get("status", "info")
            summary[status] = summary.get(status, 0) + 1
    summary["total"] = sum(summary.values())
    return summary


def _collect_suggestions(scans: List[Dict[str, List[Dict[str, str]]]]) -> List[Dict[str, str]]:
    suggestions: List[Dict[str, str]] = []
    for scan in scans:
        for check in scan["checks"]:
            if check.get("status") in {"warn", "fail"} and check.get("fix"):
                suggestions.append(
                    {
                        "scan": scan["name"],
                        "check_id": check["id"],
                        "message": check["message"],
                        "fix": check["fix"],
                    }
                )
    return suggestions


def _serialize_csv(report: Dict[str, object]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["scan", "check_id", "status", "message", "cis", "fix", "details"])
    for scan in report["scans"]:
        for check in scan["checks"]:
            writer.writerow(
                [
                    scan["name"],
                    check.get("id", ""),
                    check.get("status", ""),
                    check.get("message", ""),
                    check.get("cis", ""),
                    check.get("fix", ""),
                    check.get("details", ""),
                ]
            )
    return output.getvalue()


def _serialize_text(report: Dict[str, object]) -> str:
    lines = [
        "Zerox Report",
        f"Generated: {report['generated_at']}",
        "",
        "Summary:",
    ]
    summary = report["summary"]
    lines.append(
        " ".join(
            [
                f"total={summary.get('total', 0)}",
                f"pass={summary.get('pass', 0)}",
                f"warn={summary.get('warn', 0)}",
                f"fail={summary.get('fail', 0)}",
                f"error={summary.get('error', 0)}",
                f"fixed={summary.get('fixed', 0)}",
            ]
        )
    )
    lines.append("")
    lines.append("Suggestions:")
    if report["suggestions"]:
        for suggestion in report["suggestions"]:
            lines.append(f"- [{suggestion['scan']}] {suggestion['message']} => {suggestion['fix']}")
    else:
        lines.append("- None")
    return "\n".join(lines)


def _load_policy(policy_path: str, logger: AuditLogger) -> Dict[str, object]:
    if not os.path.exists(policy_path):
        logger.skip(f"Policy file not found: {policy_path}")
        return {}
    try:
        with open(policy_path, "r", encoding="utf-8") as handle:
            policy = json.load(handle)
    except json.JSONDecodeError:
        logger.error(f"Policy file is not valid JSON: {policy_path}")
        return {}
    if not isinstance(policy, dict):
        logger.error(f"Policy file root must be a JSON object: {policy_path}")
        return {}
    logger.info(f"Loaded policy from {policy_path}")
    return policy


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    only_flags = {
        "ssh": args.ssh_only,
        "identity": args.identity_only,
        "filesystem": args.filesystem_only,
        "network": args.network_only,
        "kernel": args.kernel_only,
        "services": args.services_only,
    }
    selected_from_only = {name for name, enabled in only_flags.items() if enabled}

    if selected_from_only and args.scan:
        parser.error("Use either --scan or --*-only flags, not both.")

    # No explicit scan choice: show help instead of running a default full scan.
    if not args.full and not args.scan and not selected_from_only:
        parser.print_help()
        return 0

    if selected_from_only:
        selected_scans = selected_from_only
    elif args.scan:
        selected_scans = set(args.scan)
    else:
        selected_scans = set(SCAN_RUNNERS.keys())

    if args.exclude_scan:
        selected_scans -= set(args.exclude_scan)

    if not selected_scans:
        parser.error("No scans selected after applying include/exclude filters.")

    if args.init_baseline:
        selected_scans.add("baseline")

    logger = AuditLogger(quiet=args.quiet, silent=(args.format != "text"))
    policy = _load_policy(args.policy, logger)
    all_scans: List[Dict[str, List[Dict[str, str]]]] = []

    all_scans.append(_collect_system_info(logger))

    for scan_name in sorted(selected_scans):
        if args.format == "text":
            logger.info("")
            logger.info(f"========== {scan_name.upper()} SCAN ==========")
        logger.info(f"Running scan: {scan_name}")
        runner = SCAN_RUNNERS[scan_name]
        result = runner(
            logger=logger,
            fix=args.fix,
            exclude_services=args.exclude,
            policy=policy,
            baseline_path=args.baseline_file,
            init_baseline=args.init_baseline,
        )
        all_scans.append(result)

    summary = _summarize(all_scans)
    suggestions = _collect_suggestions(all_scans)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "scans": all_scans,
        "suggestions": suggestions,
        "log_file": logger.log_path,
        "policy_file": args.policy,
        "baseline_file": args.baseline_file,
    }

    if args.format == "json":
        rendered = json.dumps(report, indent=2)
    elif args.format == "csv":
        rendered = _serialize_csv(report)
    else:
        rendered = _serialize_text(report)
        logger.info(
            "Summary: "
            f"total={summary['total']} pass={summary.get('pass', 0)} warn={summary.get('warn', 0)} "
            f"fail={summary.get('fail', 0)} error={summary.get('error', 0)} fixed={summary.get('fixed', 0)}"
        )
        logger.info(f"Detailed logs saved at: {logger.log_path}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered)
        if args.format == "text":
            logger.info(f"Report written to: {args.output}")
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
