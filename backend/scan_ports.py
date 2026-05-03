import nmap
import socket
import subprocess
import re
import os # Added for path checking
import sys # Added for admin check

# Refined Risky Ports with logical impact descriptions
RISKY_PORTS = {
    21: "FTP - Data and credentials are sent in plaintext. Highly vulnerable to sniffing.",
    23: "Telnet - Remote access via unencrypted channel. Legacy risk.",
    25: "SMTP - Potential for mail relay abuse if not strictly configured.",
    53: "DNS - If exposed to WAN, can be used in DNS Amplification DDoS attacks.",
    80: "HTTP - Unencrypted web traffic. Risk of session hijacking and credential theft.",
    110: "POP3 - Emails and login details sent without encryption.",
    135: "RPC - Common target for worm-based exploits and remote execution.",
    139: "NetBIOS - Can leak sensitive system names and network topology.",
    445: "SMB - High risk for Ransomware (e.g., WannaCry/EternalBlue) if exposed.",
    3389: "RDP - Frequent target for brute-force attacks and unauthorized access.",
    8080: "HTTP-Proxy/Alt - Often used for unencrypted management interfaces."
}

def classify_port_risk(port, service):
    """Logic-based risk classification for professional auditing."""
    if port in [443, 8443, 9443]:
        return "Secure", "Encrypted HTTPS service. Standard security practice."
    if port == 22:
        return "Low Risk", "SSH - Secure remote access. Ensure strong passwords/keys."
    if port in RISKY_PORTS:
        return "High Risk", RISKY_PORTS[port]
    
    insecure_keywords = ["http", "ftp", "telnet", "imap", "pop3"]
    if any(k in service.lower() for k in insecure_keywords):
        return "Medium Risk", f"Service '{service}' likely lacks encryption."

    return "Low Risk", "General service active. No immediate vulnerability signature."

def get_default_gateway():
    """Detects the gateway IP without using 'route' command."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        gateway_ip = local_ip.rsplit('.', 1)[0] + ".1"
        return gateway_ip
    except Exception:
        return "192.168.1.1"

def scan_open_ports(target_ip=None, arguments="-sT -T5 --open --top-ports 20 --host-timeout 10s"):
    """
    ULTRA-FAST SCAN MODE using Npcap engine
    """
    results = []
    
    # --- NPCAP COMPATIBILITY CHECK ---
    # On Windows, we must ensure Nmap can access the Npcap driver
    if os.name == 'nt':
        # Add Nmap to path if not present (Adjust if your Nmap is elsewhere)
        nmap_paths = [r"C:\Program Files (x86)\Nmap", r"C:\Program Files\Nmap"]
        for path in nmap_paths:
            if os.path.exists(path) and path not in os.environ["PATH"]:
                os.environ["PATH"] += os.pathsep + path

    try:
        scanner = nmap.PortScanner()
    except nmap.PortScannerError:
        print(">> Error: Nmap not found. Ensure Nmap is installed and in System PATH.")
        return results

    if not target_ip:
        target_ip = get_default_gateway()

    try:
        # Using -sT (TCP Connect) is fastest and most reliable with Npcap on Windows
        # 
        scanner.scan(hosts=target_ip, arguments=arguments)
    except Exception as e:
        print(f"Scanner Execution Error: {e}")
        return results

    if target_ip not in scanner.all_hosts():
        return results

    for proto in scanner[target_ip].all_protocols():
        ports = sorted(scanner[target_ip][proto].keys())
        for port in ports:
            port_data = scanner[target_ip][proto][port]
            
            state = port_data['state']
            service_name = port_data.get('name', 'unknown')
            product = port_data.get('product', '') 
            version = port_data.get('version', '') 
            
            risk, description = classify_port_risk(port, service_name)

            results.append({
                "target": target_ip,
                "port": port,
                "protocol": proto.upper(),
                "service": service_name.upper(),
                "product": product,
                "version": version,
                "state": state,
                "risk_level": risk,
                "description": description
            })

    return results

if __name__ == "__main__":
    # Check for Admin Privileges (Required for Npcap raw packet access)
    def is_admin():
        try: return os.getuid() == 0
        except AttributeError: return subprocess.run(['net', 'session'], capture_output=True).returncode == 0

    if not is_admin():
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("WARNING: Not running as Administrator.")
        print("Npcap requires Admin rights to perform deep scans.")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")

    gw = get_default_gateway()
    print(f"Sergent Audit Engine: Fast-Probing {gw}...")
    found_ports = scan_open_ports(gw)
    
    if not found_ports:
        print("No open ports found. This may be due to router firewall or lack of Npcap permissions.")
    
    for p in found_ports:
        print(f"[{p['risk_level']}] Port {p['port']} ({p['service']}): {p['description']}")