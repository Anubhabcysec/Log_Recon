import json
import requests
import shodan
from sqlalchemy.orm import sessionmaker
from config import Config
from database.models import IPReport, SearchHistory, PortChangeLog, create_tables

# Initialize database engine and sessionmaker
engine = create_tables()
SessionLocal = sessionmaker(bind=engine)


def calculate_risk_level(abuse_score):
    """Determine risk level based on AbuseIPDB abuse confidence score."""
    if abuse_score > 75:
        return "CRITICAL"
    elif abuse_score > 50:
        return "HIGH"
    elif abuse_score > 25:
        return "MEDIUM"
    else:
        return "LOW"


def analyze_ip(ip, db_session=None):
    """Analyze an IP address using AbuseIPDB and Shodan APIs, save results to DB, and return threat intelligence summary."""
    ip = ip.strip()
    
    # 1. Query AbuseIPDB API
    abuse_score = 0
    total_reports = 0
    country = "N/A"
    isp = "Unknown"
    domain = ""
    usage_type = ""
    hostnames = []
    
    api_key = getattr(Config, "ABUSEIPDB_API_KEY", "")
    if api_key:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": "true"
        }
        try:
            response = requests.get(url, headers=headers, params=params, timeout=8)
            if response.status_code == 200:
                data = response.json().get("data", {})
                abuse_score = data.get("abuseConfidenceScore", 0)
                total_reports = data.get("totalReports", 0)
                country = data.get("countryCode", "N/A")
                isp = data.get("isp", "Unknown")
                domain = data.get("domain", "")
                usage_type = data.get("usageType", "")
                abuse_hostnames = data.get("hostnames", [])
                if isinstance(abuse_hostnames, list):
                    hostnames = abuse_hostnames
        except Exception:
            pass

    # 2. Query Shodan API
    open_ports = []
    vulnerabilities = []
    org = "Unknown"
    
    shodan_key = getattr(Config, "SHODAN_API_KEY", "")
    if shodan_key:
        try:
            api = shodan.Shodan(shodan_key)
            host_info = api.host(ip)
            open_ports = host_info.get("ports", [])
            org = host_info.get("org", "Unknown")
            
            vulns = host_info.get("vulns", [])
            if isinstance(vulns, dict):
                vulnerabilities = list(vulns.keys())
            elif isinstance(vulns, list):
                vulnerabilities = vulns
            
            if country == "N/A":
                country = host_info.get("country_name", "N/A")
            if isp == "Unknown":
                isp = host_info.get("isp", "Unknown")
            
            # Merge Shodan hostnames with AbuseIPDB hostnames (deduplicated)
            shodan_hostnames = host_info.get("hostnames", [])
            if isinstance(shodan_hostnames, list):
                merged = list(dict.fromkeys(hostnames + shodan_hostnames))
                hostnames = merged
        except (shodan.APIError, Exception):
            # If Shodan has no data for the IP or errors out, keep shodan fields empty
            open_ports = []
            vulnerabilities = []

    # 3. Calculate risk level
    risk_level = calculate_risk_level(abuse_score)

    # 3b. Add note for Google Public DNS
    note = ""
    isp_str = (isp or "").lower()
    domain_str = (domain or "").lower()
    if ("google" in isp_str) or ("google.com" in domain_str):
        note = "Google Public DNS Server"

    # 4. Save results to database (IPReport and SearchHistory) and detect changes
    session = db_session if db_session is not None else SessionLocal()
    close_session_on_finish = (db_session is None)
    
    changes = []
    try:
        # Query previous IPReport for this IP before committing the new one
        previous_report = (
            session.query(IPReport)
            .filter(IPReport.ip_address == ip)
            .order_by(IPReport.searched_at.desc(), IPReport.id.desc())
            .first()
        )

        ip_report = IPReport(
            ip_address=ip,
            abuse_score=abuse_score,
            total_reports=total_reports,
            country=country,
            isp=isp,
            open_ports=json.dumps(open_ports),
            vulnerabilities=json.dumps(vulnerabilities),
            risk_level=risk_level
        )
        search_history = SearchHistory(
            ip_address=ip,
            risk_level=risk_level
        )
        session.add(ip_report)
        session.add(search_history)
        session.commit()

        # Compare open_ports from current scan vs previous scan
        if previous_report and previous_report.open_ports:
            try:
                prev_raw = json.loads(previous_report.open_ports)
            except Exception:
                prev_raw = []

            def _normalize_ports_map(raw_list):
                ports_dict = {}
                if isinstance(raw_list, list):
                    for item in raw_list:
                        if isinstance(item, int):
                            ports_dict[item] = ""
                        elif isinstance(item, dict):
                            p_num = item.get("port") or item.get("port_number")
                            if p_num is not None:
                                try:
                                    p_num = int(p_num)
                                    s_name = item.get("service_name") or item.get("service") or ""
                                    ports_dict[p_num] = s_name
                                except (ValueError, TypeError):
                                    pass
                return ports_dict

            prev_ports_map = _normalize_ports_map(prev_raw)
            curr_ports_map = _normalize_ports_map(open_ports)

            # Detect NEW_PORT: in current but not in previous
            for port_num, s_name in curr_ports_map.items():
                if port_num not in prev_ports_map:
                    change_log = PortChangeLog(
                        ip_address=ip,
                        port=port_num,
                        service=s_name,
                        change_type="NEW_PORT",
                        previous_value=None,
                        current_value=f"Port {port_num} ({s_name})" if s_name else f"Port {port_num}",
                    )
                    session.add(change_log)
                    changes.append(change_log.to_dict())

            # Detect CLOSED_PORT: in previous but not in current
            for port_num, prev_s_name in prev_ports_map.items():
                if port_num not in curr_ports_map:
                    change_log = PortChangeLog(
                        ip_address=ip,
                        port=port_num,
                        service=prev_s_name,
                        change_type="CLOSED_PORT",
                        previous_value=f"Port {port_num} ({prev_s_name})" if prev_s_name else f"Port {port_num}",
                        current_value=None,
                    )
                    session.add(change_log)
                    changes.append(change_log.to_dict())

            # Detect SERVICE_CHANGED: in both but service name changed
            for port_num in curr_ports_map.keys() & prev_ports_map.keys():
                prev_s = prev_ports_map[port_num]
                curr_s = curr_ports_map[port_num]
                if prev_s and curr_s and prev_s.lower() != curr_s.lower():
                    change_log = PortChangeLog(
                        ip_address=ip,
                        port=port_num,
                        service=curr_s,
                        change_type="SERVICE_CHANGED",
                        previous_value=prev_s,
                        current_value=curr_s,
                    )
                    session.add(change_log)
                    changes.append(change_log.to_dict())

            if changes:
                session.commit()

    except Exception as db_err:
        session.rollback()
        print(f"[risk_engine] DB error or change detection error: {db_err}")
    finally:
        if close_session_on_finish:
            session.close()

    # 4b. Groq AI Threat Analysis
    ai_analysis = ""
    print("Attempting AI analysis...")
    try:
        from detection.ai_analyzer import analyze_with_ai
        scan_data_for_ai = {
            "target_ip": ip,
            "scan_time": "",
            "open_ports": [{"port": p, "protocol": "tcp", "service_name": "", "service_version": ""} for p in open_ports] if open_ports else []
        }
        cve_data_for_ai = {"findings": [{"cve_id": v, "severity": "UNKNOWN", "cvss_score": 0.0, "description": ""} for v in vulnerabilities]} if vulnerabilities else {}
        mitre_data_for_ai = []
        ai_analysis = analyze_with_ai(scan_data_for_ai, cve_data_for_ai, mitre_data_for_ai)
        print("AI analysis complete")
    except Exception as ai_err:
        import traceback
        print(f"AI analysis failed: {ai_err}")
        traceback.print_exc()
        ai_analysis = f"[AI Analysis Unavailable]\n\nError: {ai_err}"

    # 5. Return formatted dictionary
    return {
        "ip": ip,
        "abuse_score": abuse_score,
        "total_reports": total_reports,
        "country": country,
        "isp": isp,
        "org": org if org != "Unknown" else isp,
        "domain": domain,
        "usage_type": usage_type,
        "hostnames": hostnames,
        "note": note,
        "open_ports": open_ports,
        "vulnerabilities": vulnerabilities,
        "risk_level": risk_level,
        "ai_analysis": ai_analysis,
        "changes": changes
    }
