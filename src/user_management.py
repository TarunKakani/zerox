# - user accounts (/etc/passwd)
# -- accounts with empty password hashes (/etc/shadow)
# -- identify if any orphan accounts (users that exist but have no owner/group)

# - PAM (pluggable auth module)
# -- password quality requirements (pam_pwquality)
# -- check lockout policies (does the system lock after 5 failed attempts?)

import pwd
import grp
import os
import re

def user_hashes():
    
    # if os.getuid != 0:
    #     return "You do not have appropriate permissions. Run as root/sudo"

    shadoow_file = "/etc/shadow"
    empty_hashes = []

    try:
        with open(shadoow_file, 'r') as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue
                
                parts = line.split(":")

                if len(parts) >= 2 and (parts[1] == "" or parts[1] == "!"):
                    empty_hashes.append(parts[0])
    except FileNotFoundError as e:
        print(f"Error: File not found {e}")
    except PermissionError:
        print("You do not have appropriate permissions. Run as root/sudo")

    return empty_hashes # these will be the locked or empty hashes account

def check_orphan_users():
    orphan_users = []

    valid_groups = {group.gr_gid for group in grp.getgrall()}
    
    for user in pwd.getpwall():
        if user.pw_gid not in valid_groups:
                orphan_users.append({'user' : user.pw_name, 'invalid_gid' : user.pw_gid})

    return orphan_users # without a group users

def pam_auth():
    pass

def rouge_user_accounts():
    rouge_accounts = []

    for user in pwd.getpwall():
        if user.pw_uid == 0 and user.pw_name != "root":
            rouge_accounts.append(user.pw_name)
    
    return rouge_accounts


print(user_hashes())
print(check_orphan_users())
print(rouge_user_accounts())
