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

    try:
        import nmap
    except ImportError:
        return {
            "target_ip": target_ip,
            "scan_time": scan_time,
            "open_ports": [],
            "error": "Nmap not available on this server. Run LogRecon locally for port scanning.",
        }

    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target_ip, arguments=arguments)

        open_ports = []
        all_hosts = nm.all_hosts()
        if not all_hosts:
            return {
                "target_ip": target_ip,
                "scan_time": scan_time,
                "open_ports": [],
            }

        for host in all_hosts:
            for protocol in nm[host].all_protocols():
                port_list = sorted(nm[host][protocol].keys())
                for port in port_list:
                    port_info = nm[host][protocol][port]
                    state = port_info.get("state", "unknown")

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

    except Exception as exc:
        # Check if error is related to missing nmap binary or port scanner error
        exc_str = str(exc).lower()
        if "nmap" in exc_str or isinstance(exc, getattr(nmap, "PortScannerError", Exception)):
            error_msg = "Nmap not available on this server. Run LogRecon locally for port scanning."
        else:
            error_msg = f"Nmap not available on this server. Run LogRecon locally for port scanning. ({exc})"
        return {
            "target_ip": target_ip,
            "scan_time": scan_time,
            "open_ports": [],
            "error": "Nmap not available on this server. Run LogRecon locally for port scanning.",
        }
