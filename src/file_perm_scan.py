# - find all files with SUID bit set to 4000 (find / -perm -4000)
# - these run as root regardless of who executes them and are prime targets for priv escl
#
# - scan for files/dirs that are writable by anyone (/tmp is okay sometimes but never in /etc)
#
# - all imp and critical file permissions 
# -- /etc/shadow (must be 600 or 400)
# -- /etc/passwd (must be 644)
# -- boot loader config (/boot/grub/grub.cfg)
#
# - check if /tmp /var /home are on seperate partitions
# -- check if /tmp is mounted with noexec and nosuid


import subprocess

def find_suid_files():

    command = "find / -perm -4000 -type f 2>/dev/null"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)

    if result.returncode == 0:
        files = result.stdout.strip().split('\n')

        print(f"Found {len(files)} SUID Binaries. Review these for potential priveledge escalation attacks.")
        
        for f in files[:files]:
            print(f"    - {f}")
        print("     ...(truncated)")
    else:
        print(f"Error running command: {result.stderr}")

find_suid_files()
