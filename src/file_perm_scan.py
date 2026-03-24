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
    
rules = {"/etc/shadow":['600', '400', '000'],
        "/etc/passwd":['644'],
        "/boot/grub/grub.cfg":['600', '400']}

for filepath, expected_params in rules.items():
    critical_files_check(filepath, expected_params)

