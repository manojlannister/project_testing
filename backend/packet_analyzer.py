from scapy.all import sniff, IP, TCP, UDP, DNS, ICMP, conf # Added conf
from collections import Counter
# Ensure your folder structure matches this import
try:
    from backend.ids_engine import IDSEngine
except ImportError:
    # Fallback if being run as a standalone test
    class IDSEngine: 
        def analyze_packet(self, pkt): pass

# --- NPCAP CONFIGURATION ---
# Forces Scapy to use the Npcap driver for raw packet access
conf.use_pcap = True 
# Set the default interface (Adjust to 'Wi-Fi' as per your Windows settings)
conf.iface = 'Wi-Fi'

class PacketAnalyzer:
    def __init__(self):
        self.packet_counts = Counter()
        self.total_packets = 0
        # Initialize the IDS Engine to analyze traffic in real-time
        self.ids = IDSEngine()

    def analyze_packet(self, pkt):
        """
        Processes each packet for both UI statistics and IDS threat detection.
        """
        if pkt.haslayer(IP):
            self.total_packets += 1
            
            # --- CONNECTION TO IDS ENGINE ---
            # This sends the raw packet to your IDS rules for threat matching
            try:
                self.ids.analyze_packet(pkt)
            except Exception as e:
                pass # Prevent analyzer crash if IDS logic fails

            # --- Protocol Identification ---
            if pkt.haslayer(TCP):
                self.packet_counts['TCP'] += 1
                # Identify Common Web Services
                if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                    self.packet_counts['HTTPS'] += 1
                elif pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                    self.packet_counts['HTTP'] += 1
            elif pkt.haslayer(UDP):
                self.packet_counts['UDP'] += 1
                if pkt.haslayer(DNS):
                    self.packet_counts['DNS'] += 1
            elif pkt.haslayer(ICMP):
                self.packet_counts['ICMP'] += 1

    def start_sniffing(self, timeout=10):
        """
        Starts the Scapy sniffer using the Npcap driver.
        """
        self.packet_counts.clear()
        self.total_packets = 0
        
        print(f">> Sniffing active on {conf.iface}... (Duration: {timeout}s)")
        
        # 
        
        try:
            # iface: explicitly targets your WiFi card
            # store=0: prevents RAM from filling up during long scans
            sniff(
                iface=conf.iface, 
                prn=self.analyze_packet, 
                timeout=timeout, 
                store=0
            )
        except Exception as e:
            print(f">> Sniffer Error: {e}. Check Admin rights/Npcap installation.")
            return []

        # Calculate percentages for the 'Traffic Protocol Distribution' UI
        results = []
        for proto, count in self.packet_counts.items():
            percentage = (count / self.total_packets) * 100 if self.total_packets > 0 else 0
            results.append({
                "protocol": proto,
                "count": count,
                "percentage": round(percentage, 1)
            })
        
        # Sort by most active protocol first
        return sorted(results, key=lambda x: x['count'], reverse=True)

def get_packet_stats(duration=10):
    """
    Interface function used by app.py during the scanning sequence.
    """
    analyzer = PacketAnalyzer()
    return analyzer.start_sniffing(timeout=duration)

if __name__ == "__main__":
    # Test execution
    print("Testing Live Packet Sniffing...")
    stats = get_packet_stats(duration=5)
    for s in stats:
        print(f"{s['protocol']}: {s['count']} packets ({s['percentage']}%)")