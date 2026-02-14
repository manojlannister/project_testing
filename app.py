from flask import Flask, render_template, Response, stream_with_context, request
import time

# Importing backend modules
from backend.scan_wifi import scan_wifi_networks
from backend.scan_ports import scan_open_ports
from backend.arp_spoof import detect_arp_spoof
from backend.devices import scan_connected_devices
from backend.score import calculate_security_score
from backend.recommendations import generate_recommendations
from backend.packet_analyzer import get_packet_stats
from backend.performance import measure_network_performance, get_usage_compatibility

# NEW: Import SQLite database logic
from backend.database import init_db, save_scan, get_history

app = Flask(
    __name__,
    template_folder="frontend/templates",
    static_folder="frontend/static"
)

# Initialize the SQLite Database on startup
init_db()

# Global storage initialized with all required fields
latest_scan_results = {
    "wifi": [],
    "ports": [],
    "arp": {"alerts": []},
    "devices": [],
    "packets": [], 
    "score": {"security_score": 100, "risk_level": "Analyzing...", "reasons": []},
    "recommendations": [],
    "usage": {"payments": 0, "movies": 0, "gaming": 0, "files": 0} 
}

# --- NAVIGATION ROUTES ---

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan")
def scan():
    return render_template("scan.html")

@app.route("/vulnerabilities")
def vulnerabilities():
    return render_template("vulnerabilities.html", 
                           wifi=latest_scan_results["wifi"], 
                           ports=latest_scan_results["ports"], 
                           arp=latest_scan_results["arp"],
                           packets=latest_scan_results["packets"],
                           score=latest_scan_results["score"],
                           usage=latest_scan_results["usage"])

@app.route("/devices")
def devices():
    return render_template("devices.html", devices=latest_scan_results["devices"])

# NEW: Route to view the Scan History table
@app.route("/history")
def history():
    data = get_history()
    return render_template("history.html", history=data)

@app.route("/report")
def report():
    return render_template("report.html", 
                           score=latest_scan_results["score"]["security_score"], 
                           risk_level=latest_scan_results["score"]["risk_level"],
                           recommendations=latest_scan_results["recommendations"],
                           open_ports=latest_scan_results["ports"],
                           devices=latest_scan_results["devices"],
                           packets=latest_scan_results["packets"],
                           wifi=latest_scan_results["wifi"],
                           usage=latest_scan_results["usage"])

# --- THE SCANNING ENGINE ---

@app.route("/api/start-scan")
def start_scan_api():
    def run_backend_logic():
        global latest_scan_results
        
        try:
            # RESET Logic - Clear previous results
            latest_scan_results["arp"]["alerts"] = []
            latest_scan_results["ports"] = []
            latest_scan_results["packets"] = []
            latest_scan_results["wifi"] = []
            latest_scan_results["devices"] = []
            latest_scan_results["usage"] = {"payments": 0, "movies": 0, "gaming": 0, "files": 0}
            
            yield "Initializing Sergent Security Core...\n"
            time.sleep(0.5)
            
            # 1. WiFi Scanning
            yield "Step 1: Mapping local WiFi environment...\n"
            latest_scan_results["wifi"] = scan_wifi_networks()
            
            # 2. Port Auditing
            yield "Step 2: Probing network ports...\n"
            latest_scan_results["ports"] = scan_open_ports()
            
            # 3. ARP Spoof Check
            yield "Step 3: Monitoring network integrity (ARP)...\n"
            latest_scan_results["arp"] = detect_arp_spoof(sniff_time=5)
            
            # 4. Traffic Inspection
            yield "Step 4: Executing Deep Packet Inspection (10s)...\n"
            latest_scan_results["packets"] = get_packet_stats(duration=10)
            
            # 5. Device Asset Mapping
            yield "Step 5: Discovering active network assets...\n"
            latest_scan_results["devices"] = scan_connected_devices()
            
            # 6. Security Scoring
            yield "Step 6: Calculating risk scores...\n"
            latest_scan_results["score"] = calculate_security_score(
                wifi_networks=latest_scan_results["wifi"], 
                open_ports=latest_scan_results["ports"], 
                arp_result=latest_scan_results["arp"], 
                devices=latest_scan_results["devices"]
            )

            # 7. Performance Benchmarking
            yield "Step 7: Benchmarking performance metrics...\n"
            perf_stats = measure_network_performance()
            latest_scan_results["usage"] = get_usage_compatibility(
                security_score=latest_scan_results["score"]["security_score"],
                perf_data=perf_stats,
                open_ports=latest_scan_results["ports"]
            )
            
            # 8. Recommendation Engine
            yield "Step 8: Generating remediation roadmap...\n"
            latest_scan_results["recommendations"] = generate_recommendations(
                wifi_networks=latest_scan_results["wifi"], 
                open_ports=latest_scan_results["ports"], 
                arp_result=latest_scan_results["arp"], 
                devices=latest_scan_results["devices"],
                score_result=latest_scan_results["score"]
            )

            # NEW: Step 9 - Save data to SQLite History
            yield "Step 9: Archiving results to local database...\n"
            save_scan(
                score=latest_scan_results["score"]["security_score"],
                risk=latest_scan_results["score"]["risk_level"],
                ssid=latest_scan_results["wifi"][0]['ssid'] if latest_scan_results["wifi"] else "Unknown",
                v_count=len(latest_scan_results["ports"])
            )
            
            yield "Analysis Complete. Data Synchronized.\n"
            yield "DONE\n"
            
        except Exception as e:
            yield f"CRITICAL SYSTEM ERROR: {str(e)}\n"
            yield "DONE\n"

    return Response(stream_with_context(run_backend_logic()), mimetype='text/plain')

if __name__ == "__main__":
    app.run(debug=True, port=5000, threaded=True)