# backend/vuln_detector.py
import logging

logger = logging.getLogger(__name__)

class VulnerabilityDetector:
    def analyze_vulnerabilities(self, port_results):
        """
        Analyzes open ports and returns SPECIFIC, dynamic vulnerability data.
        """
        detected_vulns = []
        
        for item in port_results:
            port = int(item.get('port'))
            service = item.get('service', '').lower()
            protocol = item.get('protocol', 'TCP').upper()

            # --- DYNAMIC RULE ENGINE ---
            
            # Port 80 - Standard HTTP
            if port == 80:
                detected_vulns.append({
                    'port': port, 'protocol': protocol, 'severity': 'Medium',
                    'title': 'Unencrypted HTTP Service',
                    'description': 'Standard web traffic detected without SSL encryption.',
                    'recommendation': 'Enforce HTTPS and redirect port 80 to 443.'
                })

            # Port 443 - HTTPS (Wait, why is this a risk?)
            elif port == 443:
                detected_vulns.append({
                    'port': port, 'protocol': protocol, 'severity': 'Low',
                    'title': 'SSL/TLS Service Entry Point',
                    'description': 'Encrypted port is open. Ensure the SSL certificate is valid and not self-signed.',
                    'recommendation': 'Run an SSL Labs audit to check for weak ciphers.'
                })

            # Port 8080 - Common Proxy/Dev Port
            elif port == 8080:
                detected_vulns.append({
                    'port': port, 'protocol': protocol, 'severity': 'High',
                    'title': 'Alternative HTTP (Development Port)',
                    'description': 'Port 8080 is often used for internal dashboards or dev tools, which are often poorly secured.',
                    'recommendation': 'Restrict access to local IP addresses only.'
                })

            # Port 21 - FTP
            elif "ftp" in service or port == 21:
                detected_vulns.append({
                    'port': port, 'protocol': protocol, 'severity': 'High',
                    'title': 'Cleartext FTP Detected',
                    'description': 'FTP transmits credentials in plain text, making them easy to sniff.',
                    'recommendation': 'Switch to SFTP or disable port 21.'
                })

            # Port 23 - Telnet
            elif "telnet" in service or port == 23:
                detected_vulns.append({
                    'port': port, 'protocol': protocol, 'severity': 'Critical',
                    'title': 'Legacy Telnet Service',
                    'description': 'Telnet is highly insecure and obsolete.',
                    'recommendation': 'Immediately disable Telnet and use SSH on port 22.'
                })

            # Catch-all for other ports to ensure data isn't missing
            else:
                detected_vulns.append({
                    'port': port, 'protocol': protocol, 'severity': 'Info',
                    'title': f'Active Service: {service.upper()}',
                    'description': f'Port {port} is responding. No specific CVE signature matched.',
                    'recommendation': 'If this service is not required for business, close the port.'
                })

        return detected_vulns