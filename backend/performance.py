import subprocess
import platform
import time

def measure_network_performance():
    """
    Measures real-time Ping and Jitter.
    Ping: How fast data travels (Lower is better).
    Jitter: How stable the connection is (Lower is better).
    """
    host = "8.8.8.8"
    # Use -n for Windows, -c for Linux/Mac
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "4", host]
    
    try:
        # Standardize timeout to avoid the 'hanging' scan
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, timeout=6).decode()
        
        if "time=" in output:
            # Extract numbers following 'time=' and before 'ms'
            times = [float(x.split("time=")[1].split("ms")[0]) for x in output.splitlines() if "time=" in x]
            
            if times:
                avg_ping = sum(times) / len(times)
                jitter = max(times) - min(times)
            else:
                avg_ping, jitter = 999, 999
        else:
            avg_ping, jitter = 999, 999
            
    except Exception:
        # Fallback for network timeouts or no internet access
        avg_ping, jitter = 999, 999

    return {
        "avg_ping": round(avg_ping, 2),
        "jitter": round(jitter, 2)
    }



def get_usage_compatibility(security_score, perf_data, open_ports=None):
    """
    Calculates percentage ratings for activities.
    Combines Speed (Performance) with Trust (Security).
    """
    ping = perf_data["avg_ping"]
    jitter = perf_data["jitter"]
    open_ports = open_ports or []

    # --- 1. Banking & Payments ---
    # Security is the ONLY factor that matters here.
    payment_safety = security_score * 0.95
    if security_score < 60: payment_safety *= 0.3 # Major drop for unsafe networks
    
    # --- 2. Online Gaming (Optimized Logic) ---
    # Previous logic was too strict. Updated for better real-world representation.
    if ping == 999: 
        gaming = 0
    elif ping < 60: 
        gaming = 95 # Excellent
    elif ping < 120: 
        gaming = 80 # Playable
    elif ping < 200: 
        gaming = 50 # Laggy
    else: 
        gaming = 20 # Unplayable

    # Jitter creates 'lag spikes'. We only penalize if jitter is high (>40ms)
    if jitter > 40 and jitter != 999: 
        gaming -= 20

    # --- 3. Movies & Streaming ---
    # Buffer-heavy activities care more about stability (Jitter) than pure speed.
    streaming = 100
    if ping > 250: streaming -= 20
    if jitter > 60 and jitter != 999: streaming -= 40 # Constant buffering
    
    # --- 4. File Transfer Security ---
    # High only if security is good AND no plaintext protocols (FTP/SMB) are open.
    file_security = security_score
    
    # Check for insecure file transfer ports (FTP: 21, SMB: 139/445)
    insecure_file_ports = [p for p in open_ports if p.get('port') in [21, 139, 445]]
    
    if insecure_file_ports:
        file_security -= 40 # Massive penalty for exposed file services
    
    if security_score < 70:
        file_security -= 20 # Penalty for weak encryption (WPA/Open)

    return {
        "payments": max(0, min(100, round(payment_safety))),
        "gaming": max(0, min(100, round(gaming))),
        "movies": max(0, min(100, round(streaming))),
        "files": max(0, min(100, round(file_security)))
    }