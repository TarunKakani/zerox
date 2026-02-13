- PyInstaller or Nuitka to compile the final version into a runnable binary

- Will use textual or rich for making a good tui or cli

- difflib -> Before changing a file, read the current config, 
- generate the string of the new config, and run difflib.unified_diff
- Display the diff in the terminal (colored Red for removals, Green for additions) and ask Apply this patch? [y/N].

- Async scanning (why not threads? basically async vs multi-thread?)
- asyncio Don't wait for one check to finish before starting the next. 
- Launch your "Port Scan" and "File Permission Scan" tasks concurrently. This makes the tool feel snappy.

# Now the main question -> what to scan

## Identity & Access management
- ssh config (/etc/ssh/ssh_config && sshd_config)
-- PermitRootLogin
-- PasswordAuthentication
-- PermitEmptyPasswords
-- ssh protocol up to date or sshd service check ?

- user accounts (/etc/passwd)
-- accounts with empty password hashes (/etc/shadow)
-- identify if any orphan accounts (users that exist but have no owner/group)

- PAM (pluggable auth module)
-- password quality requirements (pam_pwquality)
-- check lockout policies (does the system lock after 5 failed attempts?)

## file system & permissions
- find all files with SUID bit set to 4000 (find / -perm -4000)
- these run as root regardless of who executes them and are prime targets for priv escl

- scan for files/dirs that are writable by anyone (/tmp is okay sometimes but never in /etc)

- all imp and critical file permissions 
-- /etc/shadow (must be 600 or 400)
-- /etc/passwd (must be 644)
-- boot loader config (/boot/grub/grub.cfg)

- check if /tmp /var /home are on seperate partitions
-- check if /tmp is mounted with noexec and nosuid

## networks and firewall
- ports open and listening with protocol
- ufw, firewalld, iptables/nftables (default configs, rules configured, drop and deny)
- ip forwarding? Check /proc/sys/net/ipv4/ip_forward. Unless the machine is a router, this should be 0.
- icmp requests ? Should the server respond to pings? (Often disabled for stealth)

## kernel and system configs
- user and kernel space ? any imp settings/configs?
- systcl (/etc/sysctl.conf)
-- disable ipv6? if not needed (choice)
-- aslr?
-- core dumps?
-- ip spoofing?

- boot security - is the grub bootloader pass protected?
-- to prevent physical attackers from booting into single user-mode

## services and software
- unnessecary serviceson the system/server?
- check for updates (apt, yum, pacman, dnf)

## logging & auditing
- journald and auditd ?
- log rotation -> are logs being rotated so the disk doesn't fill up (but for which services i should check?)
- remote logging ? rsyslog?

## export to ansible ?? 
- say for example if our tool detects a missing firewall rule
- then it generates a .yml file that user can run across 100 servers

## pdf reports
- jinja2

-- Also how do i compile after completing the project into a binary that can be run and shipped to open source github


## version 2
- re-write in rust
