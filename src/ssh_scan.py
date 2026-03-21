# -- PermitRootLogin
# -- PasswordAuthentication
# -- PermitEmptyPasswords
# -- ssh protocol up to date or sshd service check ?

# also sshd_config
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
        print(f"You do not have appropriate permissions. Run as root/sudo")
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