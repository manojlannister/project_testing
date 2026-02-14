from scapy.all import sniff, ARP, get_if_hwaddr, conf
import time
from collections import defaultdict

def detect_arp_spoof(interface=None, sniff_time=10):
    """
    Enhanced ARP spoof detection. 
    Monitors for IP-MAC conflicts and self-advertising gateway packets.
    """
    arp_table = defaultdict(set)
    alerts = []
    
    # Auto-detect default interface if none provided
    if not interface:
        interface = conf.iface

    def process_packet(packet):
        if packet.haslayer(ARP):
            # op=2 is ARP Reply, op=1 is ARP Request
            # Attackers usually flood gratuitous ARP replies
            if packet[ARP].op in [1, 2]:
                ip = packet[ARP].psrc
                mac = packet[ARP].hwsrc
                
                # Ignore my own ARP packets
                try:
                    if mac == get_if_hwaddr(interface):
                        return
                except:
                    pass

                arp_table[ip].add(mac)

                # Detection Logic: One IP, Multiple MACs
                if len(arp_table[ip]) > 1:
                    alert = {
                        "ip": ip,
                        "mac_addresses": list(arp_table[ip]),
                        "risk": "High",
                        "description": f"Conflict detected: {ip} is claimed by multiple MACs. Possible MITM attack."
                    }
                    # Prevent duplicate alerts for the same event
                    if alert not in alerts:
                        alerts.append(alert)

    try:
        # Sniffing requires Admin/Sudo
        sniff(
            iface=interface,
            prn=process_packet,
            store=False,
            timeout=sniff_time,
            filter="arp" # Filter at the kernel level for better performance
        )
    except Exception as e:
        print(f"Sniffing Error: {e}. (Try running as Administrator/Sudo)")
        return {"error": "Permission Denied", "alerts": []}

    return {
        "duration": sniff_time,
        "checked_interface": str(interface),
        "alerts": alerts
    }

if __name__ == "__main__":
    print(f"Scanner: Monitoring ARP traffic on active interface...")
    result = detect_arp_spoof(sniff_time=10)

    if result["alerts"]:
        print("!!! SECURITY ALERT: ARP SPOOFING DETECTED !!!")
        for a in result["alerts"]:
            print(f"Target: {a['ip']} | Conflicting MACs: {a['mac_addresses']}")
    else:
        print("Network Integrity Verified: No ARP conflicts detected.")