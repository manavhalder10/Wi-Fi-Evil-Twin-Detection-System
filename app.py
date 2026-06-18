from flask import Flask, render_template
from datetime import datetime

app = Flask(__name__)

# Trusted Networks
trusted_networks = {
    "College_WiFi": "AA:BB:CC:DD:EE:FF",
    "Home_WiFi": "11:22:33:44:55:66"
}


import pywifi
from pywifi import const
import time

def scan_networks():

    wifi = pywifi.PyWiFi()

    iface = wifi.interfaces()[0]

    iface.scan()

    time.sleep(3)

    results = iface.scan_results()

    networks = []

    for net in results:

        networks.append({
            "ssid": net.ssid,
            "bssid": net.bssid,
            "signal": net.signal
        })

    return networks


# Evil Twin Detection Logic
def detect_evil_twin():

    scanned_networks = scan_networks()

    results = []

    for network in scanned_networks:

        status = "Safe"

        if network["ssid"] in trusted_networks:

            trusted_bssid = trusted_networks[network["ssid"]]

            if network["bssid"] != trusted_bssid:
                status = "Suspicious"

        results.append({
            "ssid": network["ssid"],
            "bssid": network["bssid"],
            "signal": network["signal"],
            "status": status,
            "time": datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        })

    return results


# Home Page
@app.route("/")
def home():
    return render_template("index.html")


# Scanner Page
@app.route("/scanner")
def scanner():

    networks = detect_evil_twin()

    return render_template(
        "scanner.html",
        networks=networks
    )


# Dashboard Page
@app.route("/dashboard")
def dashboard():

    results = detect_evil_twin()

    total = len(results)

    suspicious = len(
        [x for x in results
         if x["status"] == "Suspicious"]
    )

    safe = total - suspicious

    return render_template(
        "dashboard.html",
        results=results,
        total=total,
        safe=safe,
        suspicious=suspicious
    )


# Logs Page
@app.route("/logs")
def logs():

    scan_logs = detect_evil_twin()

    return render_template(
        "logs.html",
        logs=scan_logs
    )


# About Page
@app.route("/about")
def about():
    return render_template("about.html")


# Run Server
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )