"""
recommendations.py
Generates logical, human-readable security recommendations.
Problem -> Impact -> Solution format for laymen.
"""

def generate_recommendations(
    wifi_networks=None,
    open_ports=None,
    arp_result=None,
    devices=None,
    score_result=None
):
    recommendations = []

    # -------------------------------------------------
    # 1. Wi-Fi Encryption (The Core Risk)
    # -------------------------------------------------
    if wifi_networks and len(wifi_networks) > 0:
        net = wifi_networks[0]
        security = net.get("security_level", "").upper()
        ssid = net.get("ssid", "Current Network")

        if "OPEN" in security:
            recommendations.append({
                "title": f"Unsecured WiFi: {ssid}",
                "desc": "Your data is traveling through the air without encryption. Anyone nearby can 'sniff' your passwords. Action: Switch to WPA2 or WPA3 in router settings.",
                "severity": "Critical"
            })

        elif "WEP" in security or "WPA1" in security:
            recommendations.append({
                "title": f"Obsolete Security: {ssid}",
                "desc": "You are using WEP/WPA1. These are ancient standards that hackers can crack in under 5 minutes. Action: Upgrade to WPA2-AES immediately.",
                "severity": "High"
            })

    # -------------------------------------------------
    # 2. Open Ports (Naming the specific 3 problems)
    # -------------------------------------------------
    if open_ports:
        for port in open_ports:
            p_no = port.get("port")
            service = port.get("service", "Unknown").upper()

            # Handle Port 80 (The most common layman risk)
            if p_no == 80 or p_no == 8080:
                recommendations.append({
                    "title": f"Unencrypted Login Gateway (Port {p_no})",
                    "desc": "Your router is allowing administration via HTTP. If you log in, your password is sent like a postcard that anyone on the WiFi can read. Action: Disable HTTP and use HTTPS only.",
                    "severity": "High"
                })

            # Handle Port 53
            elif p_no == 53:
                recommendations.append({
                    "title": "Public DNS Exposure (Port 53)",
                    "desc": "Your network is visible to the global internet as a DNS server. Criminals use this to perform massive DDoS attacks. Action: Disable 'DNS WAN access' in router settings.",
                    "severity": "Medium"
                })

            # Handle Dangerous Legacy Services
            elif service in ["TELNET", "FTP"]:
                recommendations.append({
                    "title": f"Insecure Service: {service}",
                    "desc": f"The {service} protocol is 30 years old and has zero security. It is a 'Welcome' sign for hackers. Action: Disable this service immediately.",
                    "severity": "Critical"
                })

    # -------------------------------------------------
    # 3. ARP Spoofing (Active Hacking)
    # -------------------------------------------------
    if arp_result and arp_result.get("alerts"):
        recommendations.append({
            "title": "Active Intrusion Detected",
            "desc": "A device on this network is pretending to be your router (ARP Spoofing). They are likely stealing your traffic right now. Action: Disconnect immediately and use a VPN.",
            "severity": "Critical"
        })

    # -------------------------------------------------
    # 4. Device Discovery
    # -------------------------------------------------
    if devices:
        untrusted = [d for d in devices if d.get("risk") == "Untrusted"]
        if len(untrusted) > 2:
            recommendations.append({
                "title": "Unexpected Network Guests",
                "desc": f"Found {len(untrusted)} unknown devices on your network. They could be neighbors stealing your bandwidth or hackers scanning your PCs. Action: Change your WiFi password.",
                "severity": "Medium"
            })

    # -------------------------------------------------
    # 5. Overall Health Logic
    # -------------------------------------------------
    if score_result:
        score = score_result.get("security_score", 100)
        if score < 60:
            recommendations.append({
                "title": "Network Health: Critical",
                "desc": "This network failed multiple safety tests. It is unsafe for banking, work, or private browsing.",
                "severity": "High"
            })

    return recommendations

# -------------------------------------------------
# Internal Test
# -------------------------------------------------
if __name__ == "__main__":
    test = generate_recommendations(
        wifi_networks=[{"ssid": "Starbucks_WiFi", "security_level": "OPEN"}],
        open_ports=[{"port": 80, "service": "HTTP"}],
        arp_result={"alerts": []}
    )
    for r in test:
        print(f"[{r['severity']}] {r['title']}: {r['desc']}")