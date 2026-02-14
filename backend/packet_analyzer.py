from scapy.all import sniff, IP, TCP, UDP, DNS, ICMP
from collections import Counter
import threading

class PacketAnalyzer:
    def __init__(self):
        self.packet_counts = Counter()
        self.total_packets = 0
        self.is_sniffing = False

    def analyze_packet(self, pkt):
        if pkt.haslayer(IP):
            self.total_packets += 1
            # Identify Protocols
            if pkt.haslayer(TCP):
                self.packet_counts['TCP'] += 1
            elif pkt.haslayer(UDP):
                self.packet_counts['UDP'] += 1
            elif pkt.haslayer(ICMP):
                self.packet_counts['ICMP'] += 1
            
            # Identify Services
            if pkt.haslayer(DNS):
                self.packet_counts['DNS'] += 1
            if pkt.haslayer(TCP) and (pkt[TCP].dport == 443 or pkt[TCP].sport == 443):
                self.packet_counts['HTTPS'] += 1
            if pkt.haslayer(TCP) and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80):
                self.packet_counts['HTTP'] += 1

    def start_sniffing(self, timeout=10):
        self.packet_counts.clear()
        self.total_packets = 0
        sniff(prn=self.analyze_packet, timeout=timeout, store=0)
        
        # Calculate percentages for the UI
        results = []
        for proto, count in self.packet_counts.items():
            percentage = (count / self.total_packets) * 100 if self.total_packets > 0 else 0
            results.append({
                "protocol": proto,
                "count": count,
                "percentage": round(percentage, 1)
            })
        return sorted(results, key=lambda x: x['count'], reverse=True)

# Helper function for app.py
def get_packet_stats(duration=10):
    analyzer = PacketAnalyzer()
    return analyzer.start_sniffing(timeout=duration)