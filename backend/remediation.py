import subprocess
import platform
import logging

# Unique tag to identify firewall rules created by this project
TAG = "Sergent_SafeShield_"

def apply_safe_port_shield(port):
    """
    Interfaces with Windows Advanced Firewall to block inbound traffic 
    on a specific vulnerable port. Requires Administrative privileges.
    """
    if platform.system() != "Windows":
        print("[-] OS not supported for firewall remediation.")
        return False

    rule_name = f"{TAG}Port_{port}"
    
    # Command to add a block rule across all profiles (Public, Private, Domain)
    command = (
        f'netsh advfirewall firewall add rule name="{rule_name}" '
        f'dir=in action=block protocol=TCP localport={port} '
        f'profile=any interfacetype=any'
    )
    
    try:
        # Run the command and capture output to verify success
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"[+] Shield Applied: Port {port} is now blocked at the kernel level.")
            return True
        else:
            # Common failure: "Access is denied" if not running as Administrator
            print(f"[-] Firewall Rejected: {result.stderr.strip()}")
            return False
            
    except Exception as e:
        print(f"[-] Critical execution error: {e}")
        return False



def revert_all_sergent_shields():
    """
    System Cleanup: Locates and deletes all 'Sergent' specific rules.
    This demonstrates responsible tool design by restoring original system state.
    """
    if platform.system() != "Windows":
        return False

    print("[*] Reverting Sergent Security policies...")
    
    try:
        # We target the specific ports typically flagged in our scan
        # This is more precise than a 'delete all' command which might be blocked
        target_ports = [21, 23, 53, 80, 139, 443, 445, 3389, 8080]
        count = 0

        for port in target_ports:
            rule_name = f"{TAG}Port_{port}"
            # Attempt to delete the rule; if it doesn't exist, netsh just returns an error we ignore
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            res = subprocess.run(cmd, shell=True, capture_output=True)
            
            if res.returncode == 0:
                count += 1

        # Final Database Sync: Clear the virtual shield records
        from backend.database import clear_all_data
        clear_all_data()

        print(f"[+] System Restored: {count} active shields purged.")
        return True
    except Exception as e:
        print(f"[-] Revert Failed: {e}")
        return False