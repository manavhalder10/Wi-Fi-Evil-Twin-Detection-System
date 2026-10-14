
from flask import Flask, render_template
from datetime import datetime
from collections import defaultdict
import pywifi
import time

app = Flask(__name__)


# ==========================================
# TRUSTED NETWORK CONFIGURATION
# Add actual, verified SSIDs and BSSIDs.
# Multiple BSSIDs are supported per SSID.
# ==========================================

trusted_networks = {
    "OnePlus 12R": ["b2:92:97:f2:a9:e7"],
    # "College_WiFi": ["actual:bssid:here"],
    # "Home_WiFi": ["actual:bssid:here"]
}


# Normalize BSSID for consistent comparison
def normalize_bssid(bssid):
    return (bssid or "").strip().lower().rstrip(":")


# Scan nearby Wi-Fi networks
def scan_networks():
    wifi = pywifi.PyWiFi()
    interfaces = wifi.interfaces()

    if not interfaces:
        raise RuntimeError("No Wi-Fi interface found")

    iface = interfaces[0]
    iface.scan()
    time.sleep(5)

    scan_results = iface.scan_results()
    networks = []
    seen = set()

    for net in scan_results:
        raw_ssid = (net.ssid or "").strip()
        bssid = normalize_bssid(net.bssid)

        if not bssid:
            continue

        # Remove duplicate SSID/BSSID entries
        key = (raw_ssid, bssid)

        if key in seen:
            continue

        seen.add(key)

        networks.append({
            "ssid": raw_ssid or "<Hidden Network>",
            "raw_ssid": raw_ssid,
            "bssid": bssid,
            "signal": net.signal
        })

    return networks


# ==========================================
# EVIL TWIN DETECTION
# ==========================================

def detect_evil_twin():
    scanned_networks = scan_networks()
    results = []

    # Normalize trusted BSSID configuration
    trusted = {
        ssid.strip(): {
            normalize_bssid(bssid)
            for bssid in (
                addresses
                if isinstance(addresses, (list, tuple, set))
                else [addresses]
            )
        }
        for ssid, addresses in trusted_networks.items()
    }

    # Group visible SSIDs by distinct BSSID
    ssid_bssids = defaultdict(set)

    for network in scanned_networks:
        ssid = network["raw_ssid"]

        if ssid:
            ssid_bssids[ssid].add(network["bssid"])

    # Classify scanned networks
    for network in scanned_networks:
        ssid = network["raw_ssid"]
        bssid = network["bssid"]

        if not ssid:
            status = "Unsafe"
            reason = "Hidden network cannot be verified."

        elif ssid in trusted:
            if bssid in trusted[ssid]:
                status = "Safe"
                reason = "SSID and BSSID match the trusted configuration."
            else:
                status = "Unsafe"
                reason = "Trusted SSID found with an unapproved BSSID."

        elif len(ssid_bssids[ssid]) > 1:
            status = "Unsafe"
            reason = (
                "Multiple BSSIDs use this SSID. "
                "Verify whether the access points are authorized."
            )

        else:
            status = "Unsafe"
            reason = "Network is not included in the trusted configuration."

        results.append({
            "ssid": network["ssid"],
            "bssid": bssid,
            "signal": network["signal"],
            "status": status,
            "reason": reason,
            "time": datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        })

    return results


# ==========================================
# HOME PAGE
# ==========================================

@app.route("/")
def home():
    return render_template("index.html")


# ==========================================
# SCANNER PAGE
# ==========================================

@app.route("/scanner")
def scanner():
    networks = detect_evil_twin()

    return render_template(
        "scanner.html",
        networks=networks
    )


# ==========================================
# DASHBOARD PAGE
# ==========================================

@app.route("/dashboard")
def dashboard():
    results = detect_evil_twin()

    total = len(results)
    safe = sum(1 for n in results if n["status"] == "Safe")
    unsafe = sum(1 for n in results if n["status"] == "Unsafe")

    return render_template(
        "dashboard.html",
        results=results,
        total=total,
        safe=safe,
        unsafe=unsafe
    )


# ==========================================
# LOGS PAGE
# ==========================================

@app.route("/logs")
def logs():
    scan_logs = detect_evil_twin()

    return render_template(
        "logs.html",
        logs=scan_logs
    )


# ==========================================
# ABOUT PAGE
# ==========================================

@app.route("/about")
def about():
    return render_template("about.html")


# ==========================================
# RUN FLASK SERVER
# ==========================================

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
