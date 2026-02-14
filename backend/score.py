def calculate_security_score(
    wifi_networks=None,
    open_ports=None,
    arp_result=None,
    devices=None
):
    score = 100
    reasons = []

    # 1. Wi-Fi Check - ONLY penalize for the network you are actually using
    # Logic: Only check the first network (usually the connected one in scan results)
    if wifi_networks and len(wifi_networks) > 0:
        current_net = wifi_networks[0] # Assume index 0 is the target
        security = current_net.get("security_level", "").lower()

        if "open" in security:
            score -= 40
            reasons.append("Connected to an unencrypted Open Wi-Fi")
        elif "wep" in security:
            score -= 30
            reasons.append("Using highly vulnerable WEP encryption")
        elif "wpa3" in security:
            score += 5 # Bonus for high-end security
        elif "wpa2" in security:
            pass # Standard safe level

    # 2. Port Check - Cap the penalty so 10 open ports don't break the math
    if open_ports:
        high_risk_ports = [p for p in open_ports if p.get("risk_level") == "High Risk"]
        if high_risk_ports:
            # Max penalty of 30 regardless of how many ports
            penalty = min(len(high_risk_ports) * 10, 30)
            score -= penalty
            reasons.append(f"Detected {len(high_risk_ports)} high-risk open ports")

    # 3. ARP Check - Critical penalty
    if arp_result and arp_result.get("alerts"):
        score -= 40
        reasons.append("Active Man-in-the-Middle (ARP Spoofing) attempt detected")

    # 4. Device Check - Be more lenient
    if devices:
        untrusted = [d for d in devices if d.get("risk") == "Untrusted"]
        if len(untrusted) > 3: # Only warn if there are many strangers
            score -= 10
            reasons.append("Unusually high number of untrusted devices on network")

    # Bound the score
    score = max(0, min(100, score))

    if score >= 80:
        risk_level = "Low Risk (Safe)"
    elif score >= 50:
        risk_level = "Medium Risk"
    else:
        risk_level = "High Risk (Unsafe)"

    return {
        "security_score": score,
        "risk_level": risk_level,
        "reasons": list(set(reasons))
    }