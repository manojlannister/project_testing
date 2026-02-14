import sqlite3
from datetime import datetime
import os

# Database file will be created in the project root
DB_PATH = "scan_history.db"

def init_db():
    """Initializes the SQLite database and creates the scans table."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            security_score INTEGER,
            risk_level TEXT,
            wifi_ssid TEXT,
            vulnerabilities_count INTEGER
        )
    ''')
    conn.commit()
    conn.close()

def save_scan(score, risk, ssid, v_count):
    """Saves a single scan session to the database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %I:%M %p")
        cursor.execute('''
            INSERT INTO scans (timestamp, security_score, risk_level, wifi_ssid, vulnerabilities_count)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, score, risk, ssid, v_count))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Database Error: {e}")

def get_history():
    """Retrieves the last 15 scans from the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 15")
    rows = cursor.fetchall()
    conn.close()
    return rows