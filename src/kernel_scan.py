import os

def check_kernel_parameters():
    print("\n[*] Checking Kernel Security Parameters (sysctl)...")
    
    # Dictionary of parameters, their /proc paths, and the secure expected value
    kernel_params = {
        'ASLR (Address Space Layout Randomization)': {
            'path': '/proc/sys/kernel/randomize_va_space',
            'expected': '2',
            'fix': 'sysctl -w kernel.randomize_va_space=2'
        },
        'Core Dumps for SUID binaries': {
            'path': '/proc/sys/fs/suid_dumpable',
            'expected': '0',
            'fix': 'sysctl -w fs.suid_dumpable=0'
        },
        'IP Spoofing Protection (RP Filter)': {
            'path': '/proc/sys/net/ipv4/conf/all/rp_filter',
            'expected': '1',
            'fix': 'sysctl -w net.ipv4.conf.all.rp_filter=1'
        }
    }

    for name, config in kernel_params.items():
        try:
            with open(config['path'], 'r') as f:
                actual_value = f.read().strip()
                
            if actual_value == config['expected']:
                print(f"[PASS] {name} is securely configured ({actual_value}).")
            else:
                print(f"[FAIL] {name} is unsafe (Current: {actual_value}, Expected: {config['expected']}).")
        except FileNotFoundError:
            print(f"[ERROR] Could not read {name} parameter. Path not found.")

    # IPv6 is a special case (usually a warning, not a hard fail)
    try:
        with open('/proc/sys/net/ipv6/conf/all/disable_ipv6', 'r') as f:
            ipv6_status = f.read().strip()
        if ipv6_status == '1':
            print("[PASS] IPv6 is completely disabled.")
        else:
            print("[WARN] IPv6 is enabled. If not in use, consider disabling it to reduce attack surface.")
    except FileNotFoundError:
        print("[INFO] IPv6 stack not found on this system.")


def check_grub_security():
    print("\n[*] Checking Bootloader (GRUB) Security...")
    
    # Common locations for the GRUB config across different distros
    grub_paths = ['/boot/grub/grub.cfg', '/boot/grub2/grub.cfg']
    config_found = False

    for path in grub_paths:
        if os.path.exists(path):
            config_found = True
            try:
                with open(path, 'r') as f:
                    config_data = f.read()
                    
                # Look for the hashed password directive
                if 'password_pbkdf2' in config_data:
                    print(f"[PASS] GRUB bootloader menu is password protected in {path}.")
                else:
                    print(f"[FAIL] GRUB menu lacks password protection! System is vulnerable to physical boot attacks.")
            except PermissionError:
                print(f"[ERROR] Permission denied reading {path}. Run script as root to check boot security!")
            break # Only check the first valid config we find

    if not config_found:
        print("[WARN] Could not locate standard GRUB configuration file. System may use a different bootloader (e.g., systemd-boot).")

check_kernel_parameters()
check_grub_security()