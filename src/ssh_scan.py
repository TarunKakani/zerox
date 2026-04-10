# -- PermitRootLogin
# -- PasswordAuthentication
# -- PermitEmptyPasswords
# -- ssh protocol up to date or sshd service check ?

import subprocess

import subprocess

def check_sshd_service():
    print("\n[*] Checking SSH service status...")
    
    # Try 'sshd' first (RHEL/CentOS/Arch), fallback to 'ssh' (Debian/Ubuntu)
    service_name = 'sshd'
    check_cmd = subprocess.run(['systemctl', 'status', service_name], capture_output=True, text=True)
    
    if "could not be found" in check_cmd.stderr.lower() or check_cmd.returncode == 4:
        service_name = 'ssh'

    try:
        # Check if it's currently running
        active_cmd = subprocess.run(['systemctl', 'is-active', service_name], capture_output=True, text=True)
        is_active = active_cmd.stdout.strip()

        # Check if it's enabled to start on boot
        enabled_cmd = subprocess.run(['systemctl', 'is-enabled', service_name], capture_output=True, text=True)
        is_enabled = enabled_cmd.stdout.strip()

        return {
            'service_name': service_name,
            'active': is_active,
            'enabled': is_enabled
        }
    except FileNotFoundError:
        print("[-] Error: 'systemctl' command not found. Is this a systemd OS?")
        return None

service_status = check_sshd_service()
if service_status:
    print(f"  [INFO] Service Name: {service_status['service_name']}")
    print(f"  [INFO] Active State: {service_status['active']}")
    print(f"  [INFO] Boot Enabled: {service_status['enabled']}")
    
    if service_status['active'] != 'active':
        print("  [WARN] SSH service is not currently running.")


def check_ssh_config(filepath):
    print(f"Scanning {filepath}")

    # create a dictionary to store the settings we need to scan
    ssh_settings = {
        'PasswordAuthentication' : 'Not Found',
        'PermitRootLogin' : 'Not Found',
        'PermitEmptyPasswords' : 'Not Found'
    }

    try:
        with open(filepath, 'r') as file:
            for line in file:
                line = line.strip()

                if line.startswith('#') or not line:
                    continue
                
                parts = line.split()
                if len(parts) >= 2:
                    key = parts[0]
                    value = parts[1]

                    if key in ssh_settings:
                        ssh_settings[key] = value

    except FileNotFoundError as e:
        print(f"Error: File not found {e}")
    except PermissionError:
        print("You do not have appropriate permissions. Run as root/sudo")
        return None
    
    return ssh_settings


files_to_scan = [
    "/etc/ssh/ssh_config",   # Client configuration (outgoing)
    "/etc/ssh/sshd_config"   # Daemon/Server configuration (incoming)
]


for filepath in files_to_scan:
    print(f"\n[*] Starting scan of {filepath}...")
    results = check_ssh_config(filepath)

    if results:
        print(f"[+] Scanning completed for {filepath}. Evaluating results:")
        
        for key, value in results.items():
            
            if key == "PasswordAuthentication":
                if value.lower() == "yes":
                    print(f"  [WARN] {key} is 'yes'. Consider 'no' to force SSH keys.")
                else:
                    print(f"  [PASS] {key} is securely set to '{value}'.")
                    
            elif key == 'PermitRootLogin':
                if value.lower() in ["yes", "prohibit-password"]:
                    print(f"  [WARN] {key} is '{value}'. Root can login directly!")
                else:
                    print(f"  [PASS] {key} is securely set to '{value}'.")
                    
            elif key == 'PermitEmptyPasswords':
                if value.lower() == "yes":
                    print(f"  [ALERT] {key} MUST be set to 'no'")
                else:
                    print(f"  [PASS] {key} is securely set to '{value}'.")
