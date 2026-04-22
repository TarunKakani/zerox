# Improvements
- Better system info
- Simple Banner for what service got scanned not just dump all data
    - Like at start of each type of scan, print a simple "===SSH SCAN===" and give spaces b/w each scan to make it visually readible
- when run just binary without flag return help options, run normal full scan with either --full or --scan
- also correct the mistake where you added the flag --network-only. My intention was to implement flags not just for network scan only but all scans so that if the user does not want full scan everytime, he/she can do --ssh-only or --kernel-only like that. 