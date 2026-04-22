# Additional security features worth adding to Zerox (no third-party dependencies)

1. **Baseline drift detection for critical configs**
   - Save SHA-256 hashes of files like `/etc/ssh/sshd_config`, `/etc/sudoers`, `/etc/pam.d/*`, `/etc/sysctl.conf` into a local baseline file.
   - On each run, compare current hashes to baseline and flag unexpected changes.
   - Useful for catching unauthorized config tampering quickly.

2. **Expected-surface allowlisting**
   - Let users define expected listening ports and expected running services in a local policy file.
   - Report any extra open port/service as a high-priority alert.
   - This reduces noise and gives server-specific, actionable results.

3. **Sudoers hardening audit**
   - Parse `/etc/sudoers` and `/etc/sudoers.d/*` for risky patterns:
     - `NOPASSWD: ALL`
     - broad wildcards in command permissions
     - users/groups granted full root without constraints
   - This is one of the highest-value privilege escalation checks for real servers.

4. **Cron and systemd timer integrity checks**
   - Audit ownership and permissions of cron paths (`/etc/crontab`, `/etc/cron.*`) and timer unit files.
   - Flag world-writable schedule files or jobs running from writable locations.
   - Helps catch persistence mechanisms often abused after compromise.

5. **Authentication anomaly summary from local logs**
   - Parse `journalctl` or `/var/log/auth.log` for:
     - repeated failed SSH attempts by source IP
     - successful root logins
     - successful login outside normal admin windows (optional rule)
   - Provides immediate operational value, not just static misconfiguration checks.

6. **TLS certificate expiry and weakness checks**
   - Use `ssl`, `socket`, and `subprocess` (`openssl` if present) to check certificate expiration and weak signature algorithms for exposed HTTPS services.
   - Warn early on upcoming expiry or deprecated crypto usage.
   - Prevents outages and weak transport security.

7. **Kernel module attack-surface review**
   - Check loaded modules via `/proc/modules` and detect high-risk/unneeded modules (e.g., uncommon filesystems, USB storage on hardened servers).
   - Offer optional fix by writing deny rules in `/etc/modprobe.d/*.conf`.
   - Practical hardening for servers with narrow workloads.

8. **Persistence artifact triage**
   - Scan startup locations (`/etc/rc.local`, shell profiles, systemd unit overrides, `/etc/ld.so.preload`) for suspicious or unexpected entries.
   - This helps detect stealthy post-exploitation persistence without external tooling.
