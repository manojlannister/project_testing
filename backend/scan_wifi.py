import subprocess
import platform
import re


def run_command(command):
    """
    Executes an OS command safely and returns output.
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True
        )
        return result.stdout
    except Exception as e:
        return None


def classify_security(security_string):
    """
    Classifies Wi-Fi security level for risk analysis.
    """
    if not security_string or security_string.strip() == "":
        return "OPEN (High Risk)"

    sec = security_string.upper()

    if "WEP" in sec:
        return "WEP (Very High Risk)"
    elif "WPA" in sec and "WPA2" not in sec and "WPA3" not in sec:
        return "WPA (High Risk)"
    elif "WPA2" in sec:
        return "WPA2 (Moderate Risk)"
    elif "WPA3" in sec:
        return "WPA3 (Low Risk)"
    else:
        return "UNKNOWN (Risky)"


def scan_wifi_linux():
    """
    Scans Wi-Fi networks on Linux using nmcli.
    """
    networks = []

    output = run_command("nmcli -f SSID,SIGNAL,SECURITY dev wifi list")

    if not output:
        return networks

    lines = output.splitlines()[1:]  # skip header

    for line in lines:
        parts = re.split(r"\s{2,}", line.strip())
        if len(parts) >= 3:
            ssid = parts[0]
            signal = parts[1]
            security = parts[2]

            networks.append({
                "ssid": ssid,
                "signal_strength": int(signal) if signal.isdigit() else None,
                "security_raw": security,
                "security_level": classify_security(security)
            })

    return networks


def scan_wifi_windows():
    """
    Scans Wi-Fi networks on Windows using netsh.
    """
    networks = []

    output = run_command("netsh wlan show networks mode=bssid")

    if not output:
        return networks

    ssid = None
    security = None
    signal = None

    for line in output.splitlines():
        line = line.strip()

        if line.startswith("SSID"):
            ssid = line.split(":", 1)[1].strip()

        elif "Authentication" in line:
            security = line.split(":", 1)[1].strip()

        elif "Signal" in line:
            signal = line.split(":", 1)[1].strip().replace("%", "")

            networks.append({
                "ssid": ssid,
                "signal_strength": int(signal) if signal.isdigit() else None,
                "security_raw": security,
                "security_level": classify_security(security)
            })

    return networks


def scan_wifi_networks():
    """
    Main Wi-Fi scanning interface.
    Auto-detects OS and returns structured Wi-Fi security data.
    """
    os_type = platform.system()

    if os_type == "Linux":
        return scan_wifi_linux()
    elif os_type == "Windows":
        return scan_wifi_windows()
    else:
        return []


# ---------- Test Execution ----------
if __name__ == "__main__":
    wifi_networks = scan_wifi_networks()

    for net in wifi_networks:
        print(
            f"SSID: {net['ssid']} | "
            f"Signal: {net['signal_strength']} | "
            f"Security: {net['security_level']}"
        )
