import time
from collections import defaultdict
from backend.ids_rules import SIGNATURES

# Global storage for live alerts and traffic tracking
# We use this to keep track of how many packets each IP is sending
traffic_tracker = defaultdict(list)
ids_alerts = []

class IDSEngine:
    def __init__(self):
        self.rules = SIGNATURES

    def analyze_packet(self, packet):
        """
        Main analysis loop. This is called for every packet captured.
        """
        try:
            if not packet.haslayer('IP'):
                return

            src_ip = packet['IP'].src
            timestamp = time.time()
            
            # --- FEATURE 1: Detect Port Scanning/Flooding ---
            traffic_tracker[src_ip].append(timestamp)
            
            # Clean up old timestamps (older than 5 seconds) to save memory
            traffic_tracker[src_ip] = [t for t in traffic_tracker[src_ip] if timestamp - t < 5]
            
            # Check against Rule IDS-001 (Threshold check)
            scan_rule = next(r for r in self.rules if r['id'] == "IDS-001")
            if len(traffic_tracker[src_ip]) > scan_rule['threshold']:
                self.add_alert("IDS-001", src_ip, "High traffic frequency detected from source.")

            # --- FEATURE 2: Detect Plaintext Data (Sniffing) ---
            if packet.haslayer('Raw'):
                payload = packet['Raw'].load.lower()
                leak_rule = next(r for r in self.rules if r['id'] == "IDS-002")
                
                for keyword in leak_rule['keywords']:
                    if keyword in payload:
                        self.add_alert("IDS-002", src_ip, f"Sensitive keyword '{keyword.decode()}' found in plaintext!")

            # --- FEATURE 3: Detect Nmap Fingerprinting ---
            if packet.haslayer('TCP'):
                nmap_rule = next(r for r in self.rules if r['id'] == "IDS-003")
                # Nmap scans often use specific window sizes or flags
                if b"nmap" in str(packet).lower():
                    self.add_alert("IDS-003", src_ip, "Nmap scanning signature identified.")

        except Exception as e:
            # We fail silently so the packet capture doesn't stop
            pass

    def add_alert(self, rule_id, source, message):
        """Adds a unique alert to the list."""
        alert = {
            "timestamp": time.strftime('%H:%M:%S'),
            "rule_id": rule_id,
            "source": source,
            "message": message,
            "severity": next(r['name'] for r in self.rules if r['id'] == rule_id)
        }
        
        # Avoid duplicate alerts for the same event in a short time
        if not any(a['source'] == source and a['rule_id'] == rule_id for a in ids_alerts[-5:]):
            ids_alerts.append(alert)
            print(f"[!] IDS ALERT: {message} from {source}")

def get_latest_alerts():
    """Function for app.py to fetch alerts for the frontend."""
    return ids_alerts[-10:] # Return the 10 most recent alerts