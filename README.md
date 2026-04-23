# Zerox

**Zerox** is a Python-based Linux host security auditing and hardening assistant.  
It performs multi-domain checks (SSH, IAM, filesystem, network, kernel, services, persistence, TLS, and more), produces structured reports, and can apply selected safe remediations.

---

## Why Zerox

Zerox is designed for operators who need:
1. **Fast security posture visibility** on a server.
2. **Actionable findings** with suggested remediation commands.
3. **Repeatable audits** with JSON/CSV output for automation.
4. **Configuration drift detection** against a trusted local baseline.
5. **Policy-aware scanning** (expected ports/services, auth windows, TLS targets, module risk profiles).

---

## Implemented Security Coverage

### Core scans

1. **System information**
   - Host, OS, kernel, effective UID.
   - Tool availability checks (`systemctl`, `ss`, firewall tools, package managers).

2. **SSH hardening**
   - `PasswordAuthentication`, `PermitRootLogin`, `PermitEmptyPasswords`.
   - SSH service state checks.
   - Optional safe config updates with `--fix`.

3. **Identity & access (IAM)**
   - Empty password hashes in `/etc/shadow`.
   - Orphan users with invalid primary groups.
   - Rogue UID 0 users.
   - PAM policy indicators (`pam_pwquality`, lockout modules).

4. **Filesystem & permissions**
   - Critical file permissions (`/etc/shadow`, `/etc/passwd`, GRUB config).
   - World-writable artifacts in critical directories.
   - SUID binary inventory.
   - Mount hardening checks (`/tmp`, `/var`, `/home`, `noexec`, `nosuid`).

5. **Network & firewall**
   - Listening socket inventory.
   - Host firewall state (UFW / firewalld / nftables / iptables).
   - `ip_forward` and ICMP echo hardening checks.

6. **Kernel hardening**
   - ASLR, core-dump related sysctl checks, reverse-path filtering.
   - IPv6 status visibility.
   - GRUB password protection detection.

7. **Services & software hygiene**
   - Risky running service detection.
   - Package update visibility (APT/YUM/DNF/Pacman).

### Additional implemented recommendations

1. **Baseline drift detection** (`baseline` scan)
   - Hashes critical config surfaces and compares against a saved baseline file.
   - Supports baseline creation/refresh with `--init-baseline`.

2. **Expected-surface allowlisting** (`surface` scan)
   - Compares observed listening ports and running services against policy allowlists.

3. **Sudoers hardening audit** (`sudoers` scan)
   - Flags risky sudo rules such as `NOPASSWD: ALL`, broad root grants, and wildcard command grants.

4. **Cron/systemd schedule integrity** (`scheduler` scan)
   - Detects insecure cron/timer file permissions.
   - Flags scheduled jobs executing from writable targets.

5. **Authentication anomaly summary** (`authlogs` scan)
   - Summarizes repeated failed SSH attempts by source.
   - Flags root login events.
   - Optional off-hours login analysis using policy-defined admin windows.

6. **TLS certificate hygiene** (`tls` scan)
   - Checks expiry windows and weak signature algorithms on configured/discovered TLS endpoints.

7. **Kernel module attack-surface review** (`modules` scan)
   - Detects loaded high-risk modules.
   - Optional deny-rule generation in `/etc/modprobe.d/zerox-deny.conf` with `--fix`.

8. **Persistence artifact triage** (`persistence` scan)
   - Reviews startup and loader surfaces (`rc.local`, profiles, systemd unit artifacts, `ld.so.preload`).
   - Flags suspicious startup commands and writable persistence artifacts.

---

## Tech Stack

- **Language:** Python 3
- **Dependency model:** standard library only (no third-party Python packages required)
- **OS focus:** Linux hosts
- **Key built-ins used:** `argparse`, `subprocess`, `ssl`, `socket`, `hashlib`, `json`, `logging`, `os`, `stat`, `glob`, `pwd`, `grp`
- **External system tools leveraged when available:** `systemctl`, `ss`, `ufw`, `firewall-cmd`, `iptables`, `nft`, `apt`, `dnf`, `yum`, `pacman`, `journalctl`, `openssl`

---

## Project Structure

```text
src/
  zerox.py                # CLI entrypoint and scan orchestration
  audit_logger.py         # Colored console logging + persistent audit log
  ssh_scan.py
  user_management.py
  file_perm_scan.py
  network_scan.py
  kernel_scan.py
  services_scan.py
  baseline_scan.py
  surface_scan.py
  sudoers_scan.py
  scheduler_scan.py
  auth_logs_scan.py
  tls_scan.py
  kernel_modules_scan.py
  persistence_scan.py
```

---

## Installation

1. Clone the repository.
2. Ensure Python 3 is installed.
3. Run from project root.

```bash
git clone https://github.com/TarunKakani/zerox.git
cd zerox
python3 src/zerox.py --help
```

No `pip install` step is required for the core scanner.

---

## Usage

### Full scan

```bash
python3 src/zerox.py --full
```

### Run selected scans

```bash
python3 src/zerox.py --scan ssh --scan network --scan baseline
```

### Exclude scans from a full run

```bash
python3 src/zerox.py --full --exclude-scan tls --exclude-scan authlogs
```

### Legacy quick selectors

```bash
python3 src/zerox.py --ssh-only
python3 src/zerox.py --network-only
python3 src/zerox.py --services-only
```

### Output formats

```bash
python3 src/zerox.py --full --format text
python3 src/zerox.py --full --format json --output report.json
python3 src/zerox.py --full --format csv --output report.csv
```

### Safe auto-fixes

```bash
sudo python3 src/zerox.py --full --fix
```

---

## Policy File (`zerox_policy.json`)

Use a local policy file to tune environment-specific expectations.

```json
{
  "expected_ports": [22, 443],
  "expected_services": ["ssh.service", "nginx.service"],
  "tls_targets": ["example.com:443", "127.0.0.1:8443"],
  "high_risk_modules": ["usb_storage", "sctp"],
  "auth_failed_threshold": 5,
  "admin_login_hours": { "start": 8, "end": 20 },
  "allowed_startup_entries": ["/usr/local/bin/approved-startup.sh"]
}
```

Run with a custom policy path:

```bash
python3 src/zerox.py --full --policy /path/to/zerox_policy.json
```

---

## Baseline Drift Workflow

1. Create baseline from a known-good state:

```bash
sudo python3 src/zerox.py --scan baseline --init-baseline --baseline-file zerox_baseline.json
```

2. Compare future runs to baseline:

```bash
sudo python3 src/zerox.py --scan baseline --baseline-file zerox_baseline.json
```

---

## Report Model

Every scan emits normalized checks:
- `id`
- `status` (`pass`, `warn`, `fail`, `error`, `info`, `skip`, `fixed`)
- `message`
- optional metadata: `cis`, `fix`, `details`

This supports terminal-first review, machine parsing, and CI/pipeline integration.

---

## Permissions & Operational Notes

- For full coverage, run with elevated privileges (`sudo`) on Linux hosts.
- Some checks degrade gracefully when tools/files are unavailable.
- Default audit log path attempts `/var/log/my_security_audit.log`; if unavailable, it falls back to `./zerox_audit.log`.

---

## Packaging to Binary (for distribution)

If you want a single executable for release builds:

```bash
python3 -m pip install pyinstaller
pyinstaller --onefile src/zerox.py --name zerox
```

Binary output appears under `dist/zerox`.

---