from scapy.all import ARP, Ether, srp, conf
import socket
import platform
import subprocess

# --- NPCAP & INTERFACE CONFIGURATION ---
conf.use_pcap = True 
conf.iface = 'Wi-Fi' 

def get_local_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        subnet = local_ip.rsplit('.', 1)[0] + ".0/24"
        return subnet
    except:
        return None

def get_hostname(ip):
    """Attempt to resolve the hostname of a device."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown-Host"

def scan_connected_devices(subnet=None):
    devices = []
    if not subnet:
        subnet = get_local_subnet()
    if not subnet:
        return devices

    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    try:
        answered, _ = srp(packet, timeout=3, verbose=0, iface=conf.iface)
    except Exception:
        return devices

    for sent, received in answered:
        ip = received.psrc
        mac = received.hwsrc
        vendor = get_mac_vendor(mac)
        hostname = get_hostname(ip)
        
        # --- NEW FEATURE: AUTO-IDENTIFY DEVICE TYPE ---
        device_type = identify_device_category(vendor, hostname)

        devices.append({
            "ip_address": ip,
            "mac_address": mac,
            "hostname": hostname,
            "vendor": vendor,
            "device_type": device_type,
            "status": "Connected"
        })

    return devices

def identify_device_category(vendor, hostname):
    """
    Heuristic logic to separate Laptops from Androids.
    """
    v = vendor.lower()
    h = hostname.lower()

    # Android / Mobile Signatures
    mobile_vendors = ["samsung", "google", "huawei", "motorola", "xiaomi", "oppo", "vivo", "oneplus"]
    if any(x in v for x in mobile_vendors) or "android" in h:
        return "Smartphone (Android)"
    
    # Laptop / PC Signatures
    pc_vendors = ["intel", "dell", "hp", "lenovo", "asus", "acer", "realtek", "gigabyte", "msi"]
    if any(x in v for x in pc_vendors) or "desktop" in h or "laptop" in h:
        return "Laptop / PC"

    # Apple Ecosystem
    if "apple" in v:
        return "Apple Device (iPhone/Mac)"

    return "IoT / Network Node"

def get_mac_vendor(mac):
    if not mac: return "Unknown"
    prefix = mac.upper()[0:8]
    
    # Extended Vendor Map
    vendor_map = {
        "00:1A:79": "Cisco", "3C:5A:B4": "Google", "FC:C2:DE": "Samsung",
        "F4:F5:D8": "Apple", "B8:27:EB": "Raspberry Pi", "00:0C:29": "VMware",
        "08:00:27": "Oracle/VirtualBox", "A4:C3:F0": "Intel Corporate",
        "00:50:56": "VMware", "D4:3D:7E": "Micro-Star (MSI)"
    }
    return vendor_map.get(prefix, "Generic Vendor")

# ---------- Test Execution ----------
if __name__ == "__main__":
    print(f"Audit Target: {get_local_subnet()}\n")
    device_list = scan_connected_devices()

    for d in device_list:
        print(f"[{d['device_type']}] {d['ip_address']} - {d['vendor']} ({d['hostname']})")