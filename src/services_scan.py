import subprocess
import shutil

def check_risky_services():

    # list for adding the services we already know are useless or bloated
    risky_services = [
        'cups.service', 
        'avahi-daemon.service', 
        'telnet.socket', 
        'vsftpd.service', 
        'rpcbind.service'
    ]
    
    command = ['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager', '--no-legend']
    result = subprocess.run(command, stdout=subprocess.PIPE, text=True, stderr=subprocess.DEVNULL)
    
    if result.returncode == 0:
        running_services = [line.split()[0] for line in result.stdout.strip().split('\n') if line]
        
        print(f"[INFO] Found {len(running_services)} running services.")
        
        found_risky = False
        for svc in running_services:
            if svc in risky_services:
                print(f"[FAIL] Unnecessary/Risky service is actively running: {svc}")
                found_risky = True
                
        if not found_risky:
            print("[PASS] No known risky services detected.")
    else:
        print("[ERROR] Failed to run systemctl. Is this a systemd-based Linux distribution?")

def check_software_updates():
    
    # apt
    if shutil.which('apt'):
        print("[INFO] Detected APT package manager.")
      
        res = subprocess.run(['apt', 'list', '--upgradable'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        lines = res.stdout.strip().split('\n')
        
        updates = [line for line in lines if '/' in line]
        
        if updates:
            print(f"[WARN] {len(updates)} updates are available. Run 'apt upgrade' to secure the system.")
        else:
            print("[PASS] System software is up to date.")

    # dnf / yum / 
    elif shutil.which('dnf') or shutil.which('yum'):
        pm = 'dnf' if shutil.which('dnf') else 'yum'
        print(f"[INFO] Detected {pm.upper()} package manager.")
        
        res = subprocess.run([pm, 'check-update'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        
        # Remember the quirk: 100 means updates exist, 0 means up-to-date!
        if res.returncode == 100:
            print(f"[WARN] System updates are available. Run '{pm} upgrade'.")
        elif res.returncode == 0:
            print("[PASS] System software is up to date.")
        else:
            print(f"[ERROR] Package manager returned unexpected exit code: {res.returncode}")

    # pacman
    elif shutil.which('pacman'):
        print("[INFO] Detected Pacman package manager.")
        # -Qu checks for out-of-date packages
        res = subprocess.run(['pacman', '-Qu'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        
        if res.returncode == 0 and res.stdout.strip():
            lines = res.stdout.strip().split('\n')
            print(f"[WARN] {len(lines)} updates are available. Run 'pacman -Syu'.")
        else:
            print("[PASS] System software is up to date.")
            
    else:
        print("[ERROR] Could not detect a supported package manager (APT, DNF, YUM, or Pacman).")


check_risky_services()
check_software_updates()