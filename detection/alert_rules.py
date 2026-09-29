"""
detection/alert_rules.py
------------------------
Rule-based alerting engine. Evaluates scan results, log text, and abuse data
against predefined detection rules and returns triggered alerts.
"""

import json
import re
from collections import Counter
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import sessionmaker
from database.models import PortChangeLog, create_tables

# Initialize database engine and sessionmaker
engine = create_tables()
SessionLocal = sessionmaker(bind=engine)

# High-risk ports that should trigger CRITICAL_PORT alerts
CRITICAL_PORTS = {
    3389: "RDP",
    445: "SMB",
    23: "Telnet",
    21: "FTP",
}


def check_rules(scan_result, log_text="", cve_findings=None):
    """
    Evaluate scan results against all alert rules.

    Args:
        scan_result: dict from analyze_ip() containing ip, abuse_score, total_reports,
                     open_ports, vulnerabilities, risk_level, etc.
        log_text: raw log content string (optional, for brute-force detection).
        cve_findings: list of CVE dicts with cve_id, cvss_score, severity (optional).

    Returns:
        list of alert dicts, each with: rule_name, severity, message, evidence
    """
    alerts = []
    ip = scan_result.get("ip") or scan_result.get("target_ip") or "Unknown"

    # --- Rule 1: CRITICAL_PORT ---
    open_ports = scan_result.get("open_ports", [])
    for port_entry in open_ports:
        # open_ports can be a list of ints or a list of dicts
        if isinstance(port_entry, dict):
            port_num = port_entry.get("port") or port_entry.get("port_number")
            service = port_entry.get("service_name") or port_entry.get("service") or ""
        elif isinstance(port_entry, int):
            port_num = port_entry
            service = CRITICAL_PORTS.get(port_entry, "")
        else:
            continue

        try:
            port_num = int(port_num)
        except (ValueError, TypeError):
            continue

        if port_num in CRITICAL_PORTS:
            svc_label = service or CRITICAL_PORTS[port_num]
            alerts.append({
                "rule_name": "CRITICAL_PORT",
                "severity": "CRITICAL",
                "message": f"High-risk port exposed: {port_num} ({svc_label})",
                "evidence": f"Port {port_num} ({svc_label}) found open in scan results for {ip}"
            })

    # --- Rule 2: KNOWN_MALICIOUS_IP ---
    abuse_score = scan_result.get("abuse_score", 0)
    if abuse_score > 75:
        alerts.append({
            "rule_name": "KNOWN_MALICIOUS_IP",
            "severity": "CRITICAL",
            "message": f"IP flagged as malicious: {abuse_score}% confidence",
            "evidence": f"AbuseIPDB confidence score: {abuse_score}% for {ip}"
        })

    # --- Rule 3: CVE_CRITICAL ---
    if cve_findings and isinstance(cve_findings, list):
        for cve in cve_findings:
            if isinstance(cve, dict):
                cvss = cve.get("cvss_score", 0.0)
                cve_id = cve.get("cve_id", "Unknown")
                try:
                    cvss = float(cvss)
                except (ValueError, TypeError):
                    cvss = 0.0
                if cvss >= 9.0:
                    alerts.append({
                        "rule_name": "CVE_CRITICAL",
                        "severity": "CRITICAL",
                        "message": f"Critical CVE detected: {cve_id} (CVSS {cvss})",
                        "evidence": f"CVE {cve_id} with CVSS score {cvss} found for services on {ip}"
                    })

    # --- Rule 4: MULTIPLE_FAILED_LOGINS ---
    if log_text and isinstance(log_text, str):
        failed_lines = [
            line for line in log_text.splitlines()
            if "failed password" in line.lower() or "authentication failure" in line.lower()
        ]
        # Count failed attempts per source IP in log lines
        ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        source_ips = []
        for line in failed_lines:
            matches = ip_pattern.findall(line)
            source_ips.extend(matches)

        ip_counts = Counter(source_ips)
        for src_ip, count in ip_counts.items():
            if count > 3:
                alerts.append({
                    "rule_name": "MULTIPLE_FAILED_LOGINS",
                    "severity": "HIGH",
                    "message": f"Brute force detected: {count} failed login attempts",
                    "evidence": f"{count} failed password attempts from {src_ip} found in log data"
                })

        # Also check total failed lines if no specific IP found
        if not source_ips and len(failed_lines) > 3:
            alerts.append({
                "rule_name": "MULTIPLE_FAILED_LOGINS",
                "severity": "HIGH",
                "message": f"Brute force detected: {len(failed_lines)} failed login attempts",
                "evidence": f"{len(failed_lines)} failed password lines found in log data"
            })

    # --- Rule 5: PORT_CHANGE ---
    session = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)
        recent_changes = (
            session.query(PortChangeLog)
            .filter(
                PortChangeLog.ip_address == ip,
                PortChangeLog.change_type == "NEW_PORT",
                PortChangeLog.detected_at >= cutoff
            )
            .all()
        )
        for change in recent_changes:
            alerts.append({
                "rule_name": "PORT_CHANGE",
                "severity": "HIGH",
                "message": f"New port opened since last scan: {change.port}",
                "evidence": f"Port {change.port} ({change.service or 'unknown'}) detected as newly opened for {ip}"
            })
    except Exception:
        pass
    finally:
        session.close()

    # --- Rule 6: HIGH_ABUSE_REPORTS ---
    total_reports = scan_result.get("total_reports", 0)
    if total_reports > 100:
        alerts.append({
            "rule_name": "HIGH_ABUSE_REPORTS",
            "severity": "MEDIUM",
            "message": f"High abuse report count: {total_reports} reports",
            "evidence": f"AbuseIPDB shows {total_reports} abuse reports for {ip}"
        })

    return alerts
