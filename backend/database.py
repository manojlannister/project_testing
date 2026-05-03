import sqlite3
from datetime import datetime
import os

# Database file path - CRITICAL: Must match your app.py configuration
DB_PATH = "scan_history.db"

def init_db():
    """Initializes the database with History, Virtual Shield, and User tables."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 1. Scan History Table
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
    
    # 2. Virtual Protections Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS protections (
            port INTEGER PRIMARY KEY,
            status TEXT,
            timestamp TEXT
        )
    ''')

    # 3. Users Table (Stores Admin credentials and Alert Emails)
    # UNIQUE constraint on username prevents duplicate account confusion
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

# --- LOGIN SYSTEM LOGIC ---

def register_user(username, password, email):
    """Saves new admin credentials. Returns False if username exists."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        # strip() ensures no hidden spaces break the login later
        cursor.execute('''
            INSERT INTO users (username, password, email)
            VALUES (?, ?, ?)
        ''', (username.strip(), password.strip(), email.strip()))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        print(f"Registration Error: Username '{username}' already exists.")
        return False
    except Exception as e:
        print(f"Database Error: {e}")
        return False

def verify_user(username, password):
    """Checks credentials against the DB and returns the email if valid."""
    try:
        # We use DB_PATH to stay consistent with the rest of the project
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Strictly matches both username and password
        cursor.execute("SELECT email FROM users WHERE username=? AND password=?", 
                       (username.strip(), password.strip()))
        row = cursor.fetchone()
        
        conn.close()

        if row:
            return row[0]   # Returns the email address string
        return None         # Returns None if no match found
    except Exception as e:
        print(f"Verification Error: {e}")
        return None

# --- SCAN HISTORY LOGIC (UNCHANGED) ---

def save_scan(score, risk, ssid, v_count):
    """Saves a single scan session to history."""
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

def set_protection(port, active=True):
    """Tracks shielded ports in the database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        if active:
            cursor.execute('INSERT OR REPLACE INTO protections VALUES (?, ?, ?)', 
                           (port, "Shielded", datetime.now().isoformat()))
        else:
            cursor.execute('DELETE FROM protections WHERE port = ?', (port,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Protection Error: {e}")
        return False

def is_port_protected(port):
    """Checks if a port is currently marked as shielded."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT status FROM protections WHERE port = ?', (port,))
        row = cursor.fetchone()
        conn.close()
        return row is not None
    except Exception:
        return False

def get_history():
    """Retrieves the last 15 scans for the history dashboard."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 15")
        rows = cursor.fetchall()
        conn.close()
        return rows
    except Exception:
        return []

def clear_all_data():
    """Wipes all data for a clean reset - use carefully!"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans")
        cursor.execute("DELETE FROM protections")
        cursor.execute("DELETE FROM users")
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False