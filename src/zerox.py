#!/usr/bin/env python3
import os
import sys

import file_perm_scan
import kernel_scan
import network_scan
import services_scan
import ssh_scan
import user_management

def print_header(title):
    print(f"\n{'='*50}")
    print(f"[*] {title.upper()}")
    print(f"{'='*50}")

print_header("Zerox")

# File permision scanning
