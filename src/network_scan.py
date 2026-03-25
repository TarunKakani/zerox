# - ports open and listening with protocol
# - ufw, firewalld, iptables/nftables (default configs, rules configured, drop and deny)
# - ip forwarding? Check /proc/sys/net/ipv4/ip_forward. Unless the machine is a router, this should be 0.
# - icmp requests ? Should the server respond to pings? (Often disabled for stealth)

def ports_scan():
    pass


def firewall_rules_scan():
    pass

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
        
print(check_ip_forwarding())
print(check_icmp_pings())