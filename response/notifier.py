"""
response/notifier.py
--------------------
Provides Telegram alert notifications when scan findings meet or exceed configured severity thresholds.
"""

import os
import requests
from datetime import datetime

_SEVERITY_LEVELS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


def send_telegram_alert(scan_data: dict) -> bool:
    """
    Sends a formatted alert message to a configured Telegram chat if risk_level
    meets or exceeds ALERT_SEVERITY_THRESHOLD.

    Args:
        scan_data: dict containing keys such as target_ip (or ip), risk_level,
                   open_ports, cve_findings (or vulnerabilities), scan_time.

    Returns:
        bool: True if alert was sent successfully, False otherwise.
    """
    if not scan_data or not isinstance(scan_data, dict):
        return False

    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    threshold = os.environ.get("ALERT_SEVERITY_THRESHOLD", "HIGH").strip().upper()

    # Extract scan fields
    ip = scan_data.get("target_ip") or scan_data.get("ip") or "Unknown IP"
    risk_level = (scan_data.get("risk_level") or "LOW").upper()

    # Check severity threshold
    current_level_num = _SEVERITY_LEVELS.get(risk_level, 1)
    threshold_num = _SEVERITY_LEVELS.get(threshold, 3)

    if current_level_num < threshold_num:
        # Does not meet threshold
        return False

    if not bot_token or not chat_id:
        print("[Telegram Notifier] TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set. Alert skipped.")
        return False

    # Extract open ports count
    open_ports = scan_data.get("open_ports") or []
    port_count = len(open_ports) if isinstance(open_ports, list) else 0

    # Extract top finding (CVE or vulnerability)
    cve_findings = scan_data.get("cve_findings") or scan_data.get("vulnerabilities") or []
    if cve_findings and isinstance(cve_findings, list):
        first_cve = cve_findings[0]
        if isinstance(first_cve, dict):
            top_finding = first_cve.get("cve_id") or first_cve.get("description") or "Identified vulnerability"
        elif isinstance(first_cve, str):
            top_finding = first_cve
        else:
            top_finding = "Identified vulnerability"
    else:
        top_finding = "No CVEs found"

    # Format timestamp
    scan_time = scan_data.get("scan_time")
    if not scan_time:
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Format message
    message = (
        f"🚨 LogRecon Alert\n"
        f"IP: {ip}\n"
        f"Risk: {risk_level}\n"
        f"Open Ports: {port_count}\n"
        f"Top Finding: {top_finding}\n"
        f"Time: {scan_time}\n"
        f"View full report: http://localhost:5000/report/{ip}"
    )

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message
    }

    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            print(f"[Telegram Notifier] Alert sent successfully for {ip}")
            return True
        else:
            print(f"[Telegram Notifier] Telegram API error ({response.status_code}): {response.text}")
            return False
    except Exception as exc:
        print(f"[Telegram Notifier] Failed to send Telegram alert: {exc}")
        return False
