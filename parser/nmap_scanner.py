"""
parser/nmap_scanner.py
----------------------
Provides network scanning utilities using the python-nmap library.

Functions:
    scan_target(target_ip)  -- Run a service-version scan and return structured results.
    get_local_ip()          -- Return this machine's local IP address.

Usage:
    from parser.nmap_scanner import scan_target, get_local_ip

    local_ip = get_local_ip()
    results  = scan_target(local_ip)
"""

import socket
from datetime import datetime

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False


def get_local_ip() -> str:
    """
    Return the machine's primary local IP address.

    Uses a UDP connect trick (no data is actually sent) to determine which
    interface the OS would use to reach an external host, then reads the
    bound address.

    Returns:
        A string IP address (e.g. "192.168.1.42"), or "127.0.0.1" as a
        safe fallback if the network is unreachable.
    """
    try:
        # Connect to an external address (Google DNS) to determine the
        # outbound interface — no packets are sent.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def scan_target(target_ip: str, arguments: str = "-F -T4") -> dict:
    """
    Run an nmap port/service scan against a target IP address.

    Scan arguments used by default:
        -F   Fast mode: scan top 100 most common ports
        -T4  Aggressive timing for faster execution

    Args:
        target_ip: IPv4 address or hostname to scan (e.g. "192.168.1.1").
        arguments: Nmap scan flags/arguments (defaults to "-F -T4").

    Returns:
        A dict with the following keys:
            target_ip   (str)  The IP/host that was scanned.
            scan_time   (str)  ISO-8601 timestamp when the scan was started.
            open_ports  (list) List of dicts, one per open port:
                            - port           (int)  Port number.
                            - protocol       (str)  "tcp" or "udp".
                            - state          (str)  e.g. "open", "filtered".
                            - service_name   (str)  Detected service name.
                            - service_version(str)  Detected version string.
            error       (str)  Present only when scanning fails; describes
                                what went wrong.
    """
    scan_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # ------------------------------------------------------------------
    # Guard: python-nmap not importable
    # ------------------------------------------------------------------
    if not NMAP_AVAILABLE:
        return {
            "target_ip": target_ip,
            "scan_time": scan_time,
            "open_ports": [],
            "error": (
                "python-nmap is not installed. "
                "Install it with: pip install python-nmap"
            ),
        }

    # ------------------------------------------------------------------
    # Guard: nmap binary not present on the system
    # ------------------------------------------------------------------
    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError:
        return {
            "target_ip": target_ip,
            "scan_time": scan_time,
            "open_ports": [],
            "error": (
                "nmap executable not found. "
                "Please install nmap from https://nmap.org/download.html "
                "and ensure it is available on your system PATH."
            ),
        }

    # ------------------------------------------------------------------
    # Run the scan
    # ------------------------------------------------------------------
    try:
        nm.scan(hosts=target_ip, arguments=arguments)
    except nmap.PortScannerError as exc:
        return {
            "target_ip": target_ip,
            "scan_time": scan_time,
            "open_ports": [],
            "error": f"nmap scan failed: {exc}",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "target_ip": target_ip,
            "scan_time": scan_time,
            "open_ports": [],
            "error": f"Unexpected error during scan: {exc}",
        }

    # ------------------------------------------------------------------
    # Parse results
    # ------------------------------------------------------------------
    open_ports = []

    all_hosts = nm.all_hosts()
    if not all_hosts:
        # Host was unreachable or no results returned
        return {
            "target_ip": target_ip,
            "scan_time": scan_time,
            "open_ports": [],
            "error": f"No scan results returned for {target_ip}. "
                     "The host may be offline or blocking ICMP.",
        }

    for host in all_hosts:
        for protocol in nm[host].all_protocols():
            port_list = sorted(nm[host][protocol].keys())
            for port in port_list:
                port_info = nm[host][protocol][port]
                state = port_info.get("state", "unknown")

                # Only include ports that are open (or open|filtered)
                if "open" not in state:
                    continue

                open_ports.append(
                    {
                        "port": port,
                        "protocol": protocol,
                        "state": state,
                        "service_name": port_info.get("name", ""),
                        "service_version": (
                            " ".join(
                                filter(
                                    None,
                                    [
                                        port_info.get("product", ""),
                                        port_info.get("version", ""),
                                        port_info.get("extrainfo", ""),
                                    ],
                                )
                            ).strip()
                        ),
                    }
                )

    return {
        "target_ip": target_ip,
        "scan_time": scan_time,
        "open_ports": open_ports,
    }
