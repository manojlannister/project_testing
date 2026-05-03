# backend/ids_rules.py

# We define signatures with specific IDs, thresholds, and patterns.
# This makes it easy to add more rules later without changing the engine code.

SIGNATURES = [
    {
        "id": "IDS-001",
        "name": "Port Scan / DOS Attempt",
        "description": "Detection of high-frequency connection attempts from a single source.",
        "threshold": 30,  # Number of packets in a 5-second window
        "severity": "High"
    },
    {
        "id": "IDS-002",
        "name": "Plaintext Credential Leak",
        "description": "Deep Packet Inspection (DPI) found sensitive keywords in unencrypted traffic.",
        "keywords": [b"user", b"pass", b"login", b"password", b"admin", b"secret"],
        "severity": "Critical"
    },
    {
        "id": "IDS-003",
        "name": "Network Reconnaissance",
        "description": "Detection of Nmap-specific fingerprinting strings in packet payloads.",
        "pattern": "nmap",
        "severity": "Medium"
    },
    {
        "id": "IDS-004",
        "name": "Abnormal Packet Size",
        "description": "Detection of unusually large packets that could indicate data exfiltration.",
        "max_size": 1500,
        "severity": "Low"
    }
]