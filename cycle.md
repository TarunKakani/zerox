# Improvement
- show system info at start
    - which can be indirectly used to check if certain tools we are using are installed or not
    - what os is it using
- suggestion system
- and correct those suggestions on user command
- a good interface
- intentional vuln vm?

- argparse to use cli args
    - not everyone wants to scan their system all the time so we can add specific flags to initiate specific scans
- pipe the result/report to a format. Ex : Json. csv
- security rules are hardcoded into the script but yaml or json should be the ones with the rules
    - the script will read it at the start of the scan or a choice?
- logging module: instead of normal text printing to the screen we can color code and also give
    - a highly detailed, timestamped log of every single check (including standard errors)
    - gets saved to /var/log/my_security_audit.log.
- A professional script catches this gracefully and says, "[*] systemd not detected. Skipping service checks."
    - get system info
- CIS mapping?
    - Instead of just saying [FAIL] PasswordAuthentication is yes, say [FAIL] PasswordAuthentication is yes (CIS Benchmark 5.2.4).


# Features for scans

## Kernel Scan 
- Linux Kernel version ?
- 

## argparse arguments
- quiet
- exclude <service> or --network-only
- format
- output (file name)
- yaml or json security rules read
- fix (to fix the suggestions)