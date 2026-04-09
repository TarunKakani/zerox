# - ports open and listening with protocol
# - ufw, firewalld, iptables/nftables (default configs, rules configured, drop and deny)
# - ip forwarding? Check /proc/sys/net/ipv4/ip_forward. Unless the machine is a router, this should be 0.
# - icmp requests ? Should the server respond to pings? (Often disabled for stealth)

import subprocess

def ports_scan():
    command = ['ss', '-tuln'] # -t : tcp ports, -u : udp ports, -l : listening, -n : numeric ports/IP's no DNS resolution
    
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode == 0 or result.returncode == 1:

        lines = result.stdout.strip().split('\n')[1:]

        print(f"[INFO] Found {len(lines)} listening sockets. Review for unexpected services.")

        for line in lines[:5]:
            parts = line.split()
                
            print(parts)

            protoc = parts[0]
            local_addr = parts[4]
            print(f"    - {protoc.upper()} listening on {local_addr}")
        
        if len(lines) > 5:
            print("     ...(truncated)")
    else:
        print(f"[ERROR] Failed to run port scan: {result.stderr}")

def firewall_rules_scan():
    print("\n[*] Checking Firewall Status and Rules...")
    
    # 1. Check UFW (Debian/Ubuntu)
    try:
        # Replaced capture_output with stdout=subprocess.PIPE
        ufw = subprocess.run(
            ['ufw', 'status', 'verbose'], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.DEVNULL, 
            text=True
        )
        if ufw.returncode == 0: 
            if "Status: active" in ufw.stdout:
                print("[PASS] UFW firewall is ACTIVE.")
                print("    --- Active UFW Rules & Policies ---")
                lines = ufw.stdout.strip().split('\n')
                for line in lines[1:]: 
                    if line.strip():   
                        print(f"    {line}")
            else:
                print("[FAIL] UFW is installed but INACTIVE.")
            return 
    except FileNotFoundError:
        pass # UFW isn't installed, move to the next check

    # 2. Check Firewalld (RHEL/CentOS/Fedora)
    try:
        firewalld_state = subprocess.run(
            ['firewall-cmd', '--state'], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.DEVNULL, 
            text=True
        )
        if firewalld_state.returncode == 0:
            if "running" in firewalld_state.stdout:
                print("[PASS] Firewalld is ACTIVE.")
                print("    --- Active Firewalld Zone Rules ---")
                firewalld_rules = subprocess.run(
                    ['firewall-cmd', '--list-all'], 
                    stdout=subprocess.PIPE, 
                    text=True
                ).stdout
                lines = firewalld_rules.strip().split('\n')
                for line in lines:
                    print(f"    {line}")
            else:
                print("[FAIL] Firewalld is installed but INACTIVE.")
            return
    except FileNotFoundError:
        pass # Firewalld isn't installed, move to iptables

    # 3. Fallback to raw iptables
    try:
        iptables = subprocess.run(
            ['iptables', '-L', '-n'], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.DEVNULL, 
            text=True
        )
        if iptables.returncode == 0:
            print("[INFO] Raw iptables rules found.")
            print("    --- Active iptables Rules ---")
            lines = iptables.stdout.strip().split('\n')
            for line in lines[:20]:
                print(f"    {line}")
            if len(lines) > 20:
                print("    ...(truncated. Run 'sudo iptables -L -n' to see the full list)")
        else:
             print("[FAIL] No active firewall detected, or script lacks root privileges.")
    except FileNotFoundError:
        print("[FAIL] iptables command not found. System may be severely misconfigured.")

def check_ip_forwarding():
    try:
        with open("/proc/sys/net/ipv4/ip_forward", 'r') as f:
            status = f.read().strip()

            if status == '0':
                print("[SAFE] ipv4 forwarding is off.")
            else:
                print("[WARN] ipv4 forwarding is on and set to a value (1). Disable unless the server is a dedicated router")
    except FileNotFoundError:
        print("[ERROR] Could not read /proc/sys/net/ipv4/ip_forward")

def check_icmp_pings():
    try:
        with open("/proc/sys/net/ipv4/icmp_echo_ignore_all", 'r') as f:
            status = f.read().strip()

            if status == '0':
                print("[WARN] The host responds to ICMP pings. Consider disabling for stealth.")
            else:
                print("[SAFE] The host is ignoring ICMP pings (Stealth Mode).")
    except FileNotFoundError:
        print("[ERROR] Could not read /proc/sys/net/ipv4/icmp_echo_ignore_all")
        
ports_scan()
check_ip_forwarding()
check_icmp_pings()
firewall_rules_scan()