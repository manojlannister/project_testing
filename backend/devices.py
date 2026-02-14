from scapy.all import ARP, Ether, srp
import socket
import platform


def get_local_subnet():
    """
    Automatically determine local subnet (e.g., 192.168.1.0/24)
    """
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        subnet = local_ip.rsplit('.', 1)[0] + ".0/24"
        return subnet
    except:
        return None


def scan_connected_devices(subnet=None):
    """
    Discovers all devices connected to the local Wi-Fi network
    using ARP scanning.
    """

    devices = []

    if not subnet:
        subnet = get_local_subnet()

    if not subnet:
        return devices

    # Create ARP request
    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    try:
        answered, _ = srp(packet, timeout=3, verbose=0)
    except PermissionError:
        return devices

    for sent, received in answered:
        devices.append({
            "ip_address": received.psrc,
            "mac_address": received.hwsrc,
            "vendor": get_mac_vendor(received.hwsrc),
            "status": "Connected"
        })

    return devices


def get_mac_vendor(mac):
    """
    Simple MAC vendor identification (basic heuristic).
    Can be extended using an external OUI database or API.
    """
    if not mac:
        return "Unknown"

    prefix = mac.upper()[0:8]

    vendor_map = {
        "00:1A:79": "Cisco",
        "3C:5A:B4": "Google",
        "FC:C2:DE": "Samsung",
        "F4:F5:D8": "Apple",
        "B8:27:EB": "Raspberry Pi"
    }

    return vendor_map.get(prefix, "Unknown Vendor")


def identify_rogue_devices(devices, trusted_macs=None):
    """
    Flags devices that are not in the trusted MAC list.
    Useful for personal Wi-Fi networks.
    """

    if trusted_macs is None:
        trusted_macs = []

    for device in devices:
        if device["mac_address"] not in trusted_macs:
            device["risk"] = "Untrusted"
        else:
            device["risk"] = "Trusted"

    return devices


# ---------- Test Execution ----------
if __name__ == "__main__":
    print("Scanning connected devices...\n")

    device_list = scan_connected_devices()

    for d in device_list:
        print(
            f"IP: {d['ip_address']} | "
            f"MAC: {d['mac_address']} | "
            f"Vendor: {d['vendor']}"
        )
