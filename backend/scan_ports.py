import nmap
import socket
import subprocess
import re

# Refined Risky Ports with logical impact descriptions
# NOTE: Port 443 (HTTPS) is intentionally excluded as it is a security standard.
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
    """
    Logic-based risk classification for professional auditing.
    """
    # 1. Explicit Secure Ports
    if port in [443, 8443, 9443]:
        return "Secure", "Encrypted HTTPS service. Standard security practice."
    
    if port == 22:
        return "Low Risk", "SSH - Secure remote access. Ensure strong passwords/keys."

    # 2. Known Risky Ports
    if port in RISKY_PORTS:
        return "High Risk", RISKY_PORTS[port]
    
    # 3. Protocol-based check for laymen
    insecure_keywords = ["http", "ftp", "telnet", "imap", "pop3"]
    if any(k in service.lower() for k in insecure_keywords):
        return "Medium Risk", f"Service '{service}' likely lacks encryption."

    return "Low Risk", "General service active. No immediate vulnerability signature."

def get_default_gateway():
    """
    Detects the gateway IP for scanning (Windows/Linux support).
    """
    try:
        output = subprocess.check_output(['route', 'print', '0.0.0.0'], shell=True).decode()
        match = re.search(r'0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)', output)
        if match:
            return match.group(1)
    except:
        pass
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip.rsplit('.', 1)[0] + ".1"
    except Exception:
        return "192.168.1.1"



def scan_open_ports(target_ip=None, arguments="-sT -T4 --open --top-ports 100"):
    """
    Professional Nmap wrapper. 
    Accepts custom arguments to support Quick vs Deep scan modes.
    """
    results = []
    scanner = nmap.PortScanner()

    if not target_ip:
        target_ip = get_default_gateway()

    try:
        # Defaulting to top 100 ports for a balance of speed and depth
        scanner.scan(hosts=target_ip, arguments=arguments)
    except Exception as e:
        print(f"Scanner Execution Error: {e}")
        return results

    if target_ip not in scanner.all_hosts():
        return results

    for proto in scanner[target_ip].all_protocols():
        ports = sorted(scanner[target_ip][proto].keys())
        for port in ports:
            state = scanner[target_ip][proto][port]['state']
            service = scanner[target_ip][proto][port].get('name', 'unknown')
            risk, description = classify_port_risk(port, service)

            results.append({
                "target": target_ip,
                "port": port,
                "protocol": proto.upper(),
                "service": service.upper(),
                "state": state,
                "risk_level": risk,
                "description": description
            })

    return results

if __name__ == "__main__":
    gw = get_default_gateway()
    print(f"Sergent Audit Engine: Probing {gw}...")
    # Simulation of a Deep Scan
    found_ports = scan_open_ports(gw, arguments="-sT -T4 --open --top-ports 1000")
    
    for p in found_ports:
        print(f"[{p['risk_level']}] Port {p['port']} ({p['service']}): {p['description']}")