# - scan for files/dirs that are writable by anyone (/tmp is okay sometimes but never in /etc)
#
# - check if /tmp /var /home are on seperate partitions
# -- check if /tmp is mounted with noexec and nosuid

import subprocess
import os
import stat

def find_suid_files():

    command = "find / -perm -4000 -type f 2>/dev/null"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)

    if result.returncode == 0 or result.returncode == 1:
        output = result.stdout.strip()

        if output:
            files = output.split('\n')
        else:
            files = []

        print(f"Found {len(files)} SUID Binaries. Review these for potential priveledge escalation attacks.")
        
        for f in files[:5]:
            print(f"    - {f}")
        print("    - (truncated)")
    else:
        print(f"Error running command: {result.stderr}")

def critical_files_check(filepath, expected_params_list):
    
    try:
        file_stat = os.stat(filepath)
        actual_mode = stat.S_IMODE(file_stat.st_mode)
        
        actual_oct = oct(actual_mode)[2:]

        if actual_oct not in expected_params_list:
            print(f"Not safe: {filepath} has unsafe permissions {actual_oct}")
        else:
            print(f"Safe: {filepath} has safe permissions {actual_oct}")
    except FileNotFoundError:
        print(f"File does not exist {filepath}")
    except PermissionError:
        print(f"You do not have permission to access {filepath}. Run as sudo/root.")

# scanning rules
rules = {"/etc/shadow":['600', '400', '000'],
        "/etc/passwd":['644'],
        "/boot/grub/grub.cfg":['600', '400']}

for filepath, expected_params in rules.items():
    critical_files_check(filepath, expected_params)


def critical_writables_check(directories):

    vulnerable_items = []

    for directory in directories:
        if not os.path.exists(directory):
            continue # skip if a directory or path does not exists

        for root, dirs, files in os.walk(directory):
            for item in dirs + files:
                item_path = os.path.join(root, item) # join both directories and files into one list

                try:
                    mode = os.stat(item_path).st_mode
                        
                        # ??
                    if mode & stat.S_IWOTH:
                        vulnerable_items.append(item_path)
                    
                except (FileNotFoundError, PermissionError):
                    continue # skip these files if running without root or sudo
    
    return vulnerable_items

# scanning dirs
# bin vs sbin vs /usr/bin vs /usr/local/bin??
# what about /dev/shm?
critical_dirs = ['/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin', '/dev/shm']

bad_files = critical_writables_check(critical_dirs)

if bad_files:
    print(f"[FAIL] Found {len(bad_files)} world-writable items!")
    for f in bad_files[:10]:
        print(f"   - {f}")
    if len(bad_files) > 10:
        print("   ...(truncated)")
else:
    print("[PASS] No world-writable files found in critical directories.")

find_suid_files()

