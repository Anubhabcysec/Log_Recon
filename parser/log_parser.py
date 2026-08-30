"""
parser/log_parser.py
--------------------
Utility functions for detecting log formats, parsing raw text logs,
and extracting Windows EVTX event logs for incident response analysis.
"""

import re
import ipaddress
from datetime import datetime

# Optional import for EVTX handling
try:
    import Evtx.Evtx as evtx
    from xml.etree import ElementTree as ET
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False


# IP address pattern: matches valid IPv4 representations
_IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

# Common timestamp patterns
_TIMESTAMP_PATTERNS = [
    # ISO-8601 / RFC 3339: 2026-08-25T00:34:10 or 2026-08-25 00:34:10
    re.compile(r'\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b'),
    # Syslog / Auth log: Aug 25 00:34:10 or Aug  5 00:34:10
    re.compile(r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b'),
    # Common Log Format (Nginx / Apache): 25/Aug/2026:00:34:10 +0000
    re.compile(r'\b\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?\b'),
]

# Keywords for classification
_ERROR_KEYWORDS = ["ERROR", "FAILED", "CRITICAL", "WARNING"]
_SUSPICIOUS_KEYWORDS = [
    "failed password",
    "invalid user",
    "refused",
    "attack",
    "inject",
    "scanner",
    "brute"
]


def detect_log_type(content: str) -> str:
    """
    Looks at the first few lines of log content and classifies the format.

    Returns:
        One of: "ssh_auth", "nginx", "apache", "windows_event", "syslog", "unknown"
    """
    if not content or not isinstance(content, str):
        return "unknown"

    lines = [line.strip() for line in content.strip().splitlines() if line.strip()][:30]
    if not lines:
        return "unknown"

    sample = "\n".join(lines).lower()

    # Windows Event / XML representation
    if "<event" in sample or "<renderinginfo" in sample or "eventid" in sample or "microsoft-windows" in sample:
        return "windows_event"

    # SSH / Auth logs
    if "sshd[" in sample or "sshd:" in sample or "failed password for" in sample or "accepted password for" in sample or "pam_unix(sshd" in sample:
        return "ssh_auth"

    # Nginx access or error log
    if "nginx" in sample or ' "get ' in sample or ' "post ' in sample:
        if "[" in sample and "]" in sample and ('"http/' in sample or 'http/1.' in sample or 'http/2.' in sample):
            return "nginx"

    # Apache access or error log
    if "apache" in sample or "httpd" in sample:
        return "apache"

    # Common Web Server combined format default (Nginx/Apache)
    if re.search(r'^\S+ \S+ \S+ \[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}', lines[0]):
        return "nginx"

    # Generic syslog format (e.g., Aug 25 12:00:00 hostname process[123]: msg)
    if re.search(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+:', lines[0]):
        return "syslog"

    return "unknown"


def _extract_ips(text: str) -> list:
    """Extract and validate unique IPv4 addresses from text while preserving order."""
    matches = _IPV4_PATTERN.findall(text)
    unique_ips = []
    seen = set()
    for ip in matches:
        try:
            ipaddress.ip_address(ip)
            if ip not in seen:
                seen.add(ip)
                unique_ips.append(ip)
        except ValueError:
            continue
    return unique_ips


def _extract_timestamps(lines: list) -> tuple:
    """Find the first and last timestamps across lines."""
    timestamps = []
    for line in lines:
        for pattern in _TIMESTAMP_PATTERNS:
            found = pattern.findall(line)
            if found:
                timestamps.extend(found)
                break
    if not timestamps:
        return None, None
    return timestamps[0], timestamps[-1]


def parse_text_log(content: str) -> dict:
    """
    Parses raw log text and returns a summary dict.

    Returns:
        dict: {
            "log_type": str,
            "total_lines": int,
            "error_lines": list (max 50),
            "suspicious_lines": list (max 50),
            "ip_addresses": list,
            "time_range": tuple (first_timestamp, last_timestamp) or None
        }
    """
    if not content:
        content = ""

    lines = content.splitlines()
    total_lines = len(lines)
    log_type = detect_log_type(content)

    error_lines = []
    suspicious_lines = []

    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue

        line_upper = line_clean.upper()
        line_lower = line_clean.lower()

        # Check for error keywords
        if len(error_lines) < 50:
            if any(err_kw in line_upper for err_kw in _ERROR_KEYWORDS):
                error_lines.append(line_clean)

        # Check for suspicious keywords
        if len(suspicious_lines) < 50:
            if any(sus_kw in line_lower for sus_kw in _SUSPICIOUS_KEYWORDS):
                suspicious_lines.append(line_clean)

    # Extract unique IPs
    ip_addresses = _extract_ips(content)

    # Time range
    first_ts, last_ts = _extract_timestamps(lines)
    time_range = (first_ts, last_ts) if first_ts else None

    return {
        "log_type": log_type,
        "total_lines": total_lines,
        "error_lines": error_lines,
        "suspicious_lines": suspicious_lines,
        "ip_addresses": ip_addresses,
        "time_range": time_range
    }


def parse_evtx_log(filepath: str) -> dict:
    """
    Parses a Windows .evtx file, extracts EventID, TimeCreated, Message for each event,
    and returns a summary dictionary in the same format as parse_text_log().

    Returns:
        dict with log_type, total_lines, error_lines, suspicious_lines, ip_addresses, time_range.
    """
    if not EVTX_AVAILABLE:
        return {
            "log_type": "windows_event",
            "total_lines": 0,
            "error_lines": ["[Error] python-evtx package is not installed"],
            "suspicious_lines": [],
            "ip_addresses": [],
            "time_range": None
        }

    formatted_event_lines = []
    error_lines = []
    suspicious_lines = []
    all_ips_set = set()
    all_ips = []
    timestamps = []

    try:
        with evtx.Evtx(filepath) as log:
            for record in log.records():
                try:
                    xml_content = record.xml()
                    root = ET.fromstring(xml_content)
                    
                    # Extract namespace if present
                    ns = ""
                    if root.tag.startswith("{"):
                        ns = root.tag.split("}")[0] + "}"

                    # Extract System Header data
                    event_id_elem = root.find(f".//{ns}EventID")
                    event_id = event_id_elem.text if event_id_elem is not None else "N/A"

                    time_created_elem = root.find(f".//{ns}TimeCreated")
                    time_created = (
                        time_created_elem.attrib.get("SystemTime", "N/A")
                        if time_created_elem is not None
                        else "N/A"
                    )
                    if time_created != "N/A":
                        timestamps.append(time_created)

                    level_elem = root.find(f".//{ns}Level")
                    level = level_elem.text if level_elem is not None else ""

                    # Extract EventData or UserData message values
                    data_elements = root.findall(f".//{ns}Data")
                    message_parts = [d.text for d in data_elements if d.text]
                    message = " | ".join(message_parts) if message_parts else ""

                    line_str = f"[{time_created}] EventID:{event_id} Level:{level} - {message}"
                    formatted_event_lines.append(line_str)

                    # Extract IPs from event XML
                    for ip in _IPV4_PATTERN.findall(xml_content):
                        if ip not in all_ips_set:
                            try:
                                ipaddress.ip_address(ip)
                                all_ips_set.add(ip)
                                all_ips.append(ip)
                            except ValueError:
                                pass

                    line_upper = line_str.upper()
                    line_lower = line_str.lower()

                    # Errors / Critical levels (Level 1=Critical, Level 2=Error, Level 3=Warning in EVTX)
                    if len(error_lines) < 50:
                        if level in ["1", "2", "3"] or any(k in line_upper for k in _ERROR_KEYWORDS):
                            error_lines.append(line_str)

                    # Suspicious keywords
                    if len(suspicious_lines) < 50:
                        if any(k in line_lower for k in _SUSPICIOUS_KEYWORDS):
                            suspicious_lines.append(line_str)

                except Exception:
                    continue

    except Exception as e:
        error_lines.append(f"Failed to parse EVTX file: {str(e)}")

    time_range = (timestamps[0], timestamps[-1]) if timestamps else None

    return {
        "log_type": "windows_event",
        "total_lines": len(formatted_event_lines),
        "error_lines": error_lines,
        "suspicious_lines": suspicious_lines,
        "ip_addresses": all_ips,
        "time_range": time_range
    }


def find_local_logs() -> list:
    """
    Scans standard Windows log file locations:
      - C:\\Windows\\System32\\winevt\\Logs\\Application.evtx
      - C:\\Windows\\System32\\winevt\\Logs\\System.evtx
      - C:\\Users\\{username}\\AppData\\Local\\Temp\\ (*.log files)

    Returns:
        list of dicts: [
            {"name": str, "path": str, "size_kb": float, "type": str}, ...
        ]
    """
    import os

    found = []
    
    # 1. System Windows Event Logs
    sys_paths = [
        (r"C:\Windows\System32\winevt\Logs\Application.evtx", "Application.evtx", "EVTX"),
        (r"C:\Windows\System32\winevt\Logs\System.evtx", "System.evtx", "EVTX"),
    ]

    for path, name, log_type in sys_paths:
        if os.path.exists(path):
            try:
                size_bytes = os.path.getsize(path)
                found.append({
                    "name": name,
                    "path": path,
                    "size_kb": round(size_bytes / 1024, 1),
                    "type": log_type
                })
            except (OSError, PermissionError):
                # Include path with 0 kb if accessible or skip
                pass

    # 2. Temp directory logs for current user
    username = os.environ.get('USERNAME', '')
    if username:
        temp_dir = os.path.join(r"C:\Users", username, r"AppData\Local\Temp")
    else:
        temp_dir = os.environ.get('TEMP', '')

    if temp_dir and os.path.exists(temp_dir):
        try:
            for entry in os.listdir(temp_dir):
                if entry.lower().endswith('.log'):
                    full_path = os.path.join(temp_dir, entry)
                    if os.path.isfile(full_path):
                        try:
                            size_bytes = os.path.getsize(full_path)
                            found.append({
                                "name": entry,
                                "path": full_path,
                                "size_kb": round(size_bytes / 1024, 1),
                                "type": "TEXT"
                            })
                        except (OSError, PermissionError):
                            continue
        except (OSError, PermissionError):
            pass

    return found

