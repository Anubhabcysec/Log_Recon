import os
import json
import ipaddress
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, send_file, Response
from sqlalchemy.orm import sessionmaker

from config import Config
from database.models import SearchHistory, IPReport, ScheduledScan, FalsePositive, create_tables
from detection.risk_engine import analyze_ip
from parser.nmap_scanner import scan_target, get_local_ip
from parser.log_parser import parse_text_log, parse_evtx_log, find_local_logs
from detection.cve_lookup import get_cves_for_service
from detection.mitre_mapper import map_ports_to_mitre
from detection.ai_analyzer import analyze_with_ai
from detection.log_analyzer import analyze_log_with_ai
from response.pdf_generator import generate_pdf_report
from response.notifier import send_telegram_alert
from response.scheduler import start_scheduler
import tempfile
from datetime import timedelta

app = Flask(
    __name__,
    template_folder='dashboard/templates',
    static_folder='dashboard/static'
)
app.config.from_object(Config)

# Initialize database engine and sessionmaker
engine = create_tables()
SessionLocal = sessionmaker(bind=engine)

# Custom Jinja2 filter to parse JSON strings in templates
app.jinja_env.filters['from_json'] = lambda s: json.loads(s) if s else []


def is_valid_ip(ip_str):
    """Validate whether the given string is a valid IPv4 or IPv6 address format."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


# --- FLASK ROUTES ---

@app.route('/')
def home():
    """Redirect root path to /dashboard."""
    return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard():
    """Security dashboard showcasing core capabilities and real-time System Pulse."""
    session = SessionLocal()
    try:
        recent_history = session.query(SearchHistory).order_by(SearchHistory.searched_at.desc()).limit(5).all()
    except Exception as e:
        recent_history = []
    finally:
        session.close()

    return render_template('dashboard.html', recent_history=recent_history)


@app.route('/analyze', methods=['POST'])
def analyze():
    """POST route that accepts an IP address and redirects to report page."""
    ip = request.form.get('ip', '').strip()
    
    # Validation
    if not ip or not is_valid_ip(ip):
        flash(f"'{ip}' is not a valid IPv4 or IPv6 address format.", "error")
        return redirect(url_for('dashboard'))

    return redirect(url_for('report', ip=ip))


@app.route('/report/<ip>')
def report(ip):
    """Shows full threat report for a given IP address by calling analyze_ip()."""
    ip = ip.strip()
    
    # Basic IP address format validation before querying
    if not is_valid_ip(ip):
        flash(f"'{ip}' is not a valid IPv4 or IPv6 address format.", "error")
        return redirect(url_for('home'))

    # Call analyze_ip from detection.risk_engine
    result = analyze_ip(ip)

    # Format helpers for template compatibility
    abuse_data = {
        "abuseConfidenceScore": result.get("abuse_score", 0),
        "totalReports": result.get("total_reports", 0),
        "countryCode": result.get("country", "N/A"),
        "countryName": "",
        "isp": result.get("isp", "Unknown"),
        "domain": "N/A",
        "usageType": "N/A",
        "isWhitelisted": False
    }

    shodan_data = {
        "ports": result.get("open_ports", []),
        "vulns": result.get("vulnerabilities", []),
        "isp": result.get("isp", "Unknown"),
        "org": result.get("isp", "Unknown"),
        "os": "Unknown / Undetected",
        "hostnames": []
    }

    pretty_json = json.dumps(result, indent=2)

    return render_template(
        'report.html',
        ip=ip,
        result=result,
        abuse=abuse_data,
        shodan=shodan_data,
        raw_json_pretty=pretty_json
    )


@app.route('/api/analyze/<ip>')
def api_analyze(ip):
    """JSON endpoint that validates IP, calls analyze_ip(), and returns combined results as JSON."""
    ip = ip.strip()
    
    # Basic IP address format validation before querying
    if not is_valid_ip(ip):
        return jsonify({
            "status": "error",
            "message": f"'{ip}' is not a valid IPv4 or IPv6 address format."
        }), 400

    # Call analyze_ip from detection.risk_engine
    result = analyze_ip(ip)

    # Ensure ai_analysis is populated via analyze_with_ai if not already present
    if not result.get("ai_analysis"):
        try:
            scan_data = {
                "target_ip": ip,
                "scan_time": "",
                "open_ports": [{"port": p, "protocol": "tcp", "service_name": "", "service_version": ""} for p in result.get("open_ports", [])]
            }
            cve_data = {"findings": [{"cve_id": v, "severity": "UNKNOWN", "cvss_score": 0.0, "description": ""} for v in result.get("vulnerabilities", [])]} if result.get("vulnerabilities") else {}
            mitre_data = []
            result["ai_analysis"] = analyze_with_ai(scan_data, cve_data, mitre_data)
        except Exception as ai_err:
            result["ai_analysis"] = f"[AI Analysis Unavailable]\n\nError: {ai_err}"

    # Send Telegram alert if risk meets configured threshold
    try:
        send_telegram_alert(result)
    except Exception as e:
        print(f"[api_analyze] Telegram alert error: {e}")

    return jsonify({
        "status": "success",
        "data": result,
        "ai_analysis": result.get("ai_analysis", "")
    })


@app.route('/history')
def history():
    """Shows all previously searched IPs by querying SearchHistory from the database."""
    session = SessionLocal()
    try:
        # Query SearchHistory from database
        records = session.query(SearchHistory).order_by(SearchHistory.searched_at.desc()).all()
    finally:
        session.close()

    return render_template('history.html', history=records)


@app.route('/history/clear', methods=['POST'])
def clear_history():
    """Clear all historical search records from database."""
    session = SessionLocal()
    try:
        session.query(SearchHistory).delete()
        session.query(IPReport).delete()
        session.commit()
        flash("Search history has been cleared.", "info")
    except Exception as e:
        session.rollback()
        flash(f"Failed to clear history: {str(e)}", "error")
    finally:
        session.close()
    return redirect(url_for('history'))


@app.route('/api/local-ip')
def api_local_ip():
    """Returns local IP address of host system."""
    return jsonify({"status": "success", "ip": get_local_ip()})


@app.route('/api/local_ip')
def api_local_ip_underscore():
    """Returns local IP address of host system as JSON {"ip": "<ip>"}."""
    return jsonify({"ip": get_local_ip()})


@app.route('/scan')
@app.route('/scanner')
def scanner():
    """Scanner page for running deep port scan, CVE lookup, MITRE mapping, and AI analysis."""
    target_ip = request.args.get('ip', '').strip()
    return render_template('scanner.html', mode='ip', target_ip=target_ip)


@app.route('/scan/ip')
def scan_ip():
    """Scanner page configured for public IP address analysis."""
    target_ip = request.args.get('ip', '').strip()
    return render_template('scanner.html', mode='ip', target_ip=target_ip)


@app.route('/scan/local')
def scan_local():
    """Scanner page configured to automatically trigger local IP scanning on page load."""
    return render_template('scanner.html', mode='local')


@app.route('/logs')
def logs():
    """Renders the Log Analyzer page."""
    return render_template('logs.html')


@app.route('/reports')
def reports():
    """Renders the Reports page showing all past scan reports."""
    session = SessionLocal()
    try:
        all_reports = session.query(IPReport).order_by(IPReport.searched_at.desc()).all()
        return render_template('reports.html', reports=all_reports)
    finally:
        session.close()


@app.route('/api/analyze-log', methods=['POST'])
def api_analyze_log():
    """
    POST route that analyzes uploaded log files (.log, .txt, .evtx) or raw pasted text.
    Calls parser.log_parser and detection.log_analyzer, returning structured findings.
    """
    try:
        raw_text = ""
        is_evtx = False
        temp_evtx_path = None

        # 1. Check for file upload
        if 'logfile' in request.files and request.files['logfile'].filename != '':
            uploaded_file = request.files['logfile']
            filename = uploaded_file.filename.lower()

            if filename.endswith('.evtx'):
                is_evtx = True
                # Save temporarily for python-evtx parser
                with tempfile.NamedTemporaryFile(delete=False, suffix='.evtx') as tf:
                    uploaded_file.save(tf.name)
                    temp_evtx_path = tf.name
            else:
                # Read text log with fallback encoding
                file_bytes = uploaded_file.read()
                try:
                    raw_text = file_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    import chardet
                    detected = chardet.detect(file_bytes)
                    encoding = detected.get('encoding') or 'latin-1'
                    raw_text = file_bytes.decode(encoding, errors='replace')
        else:
            # 2. Check for pasted text
            raw_text = request.form.get('logtext', '')
            if not raw_text and request.is_json:
                raw_text = (request.get_json(silent=True) or {}).get('logtext', '')

        if not is_evtx and not raw_text.strip():
            return jsonify({"error": "No log content or file was provided."}), 400

        # 3. Parse log content
        if is_evtx and temp_evtx_path:
            try:
                parsed_data = parse_evtx_log(temp_evtx_path)
            finally:
                if os.path.exists(temp_evtx_path):
                    try:
                        os.remove(temp_evtx_path)
                    except OSError:
                        pass
            raw_sample = "\n".join(parsed_data.get("suspicious_lines", []) + parsed_data.get("error_lines", []))[:3000]
        else:
            parsed_data = parse_text_log(raw_text)
            raw_sample = raw_text[:3000]

        # 4. Perform AI Analysis
        ai_analysis = analyze_log_with_ai(parsed_data, raw_sample)

        # 5. Determine severity based on suspicious line count
        suspicious_count = len(parsed_data.get("suspicious_lines", []))
        error_count = len(parsed_data.get("error_lines", []))

        if suspicious_count >= 10:
            severity = "CRITICAL"
        elif suspicious_count >= 5:
            severity = "HIGH"
        elif suspicious_count >= 1:
            severity = "MEDIUM"
        elif error_count > 0:
            severity = "LOW"
        else:
            severity = "LOW"

        # 6. Return response JSON
        return jsonify({
            "log_type": parsed_data.get("log_type", "unknown"),
            "total_lines": parsed_data.get("total_lines", 0),
            "error_count": error_count,
            "suspicious_count": suspicious_count,
            "suspicious_lines": parsed_data.get("suspicious_lines", []),
            "error_lines": parsed_data.get("error_lines", []),
            "ip_addresses": parsed_data.get("ip_addresses", []),
            "ai_analysis": ai_analysis,
            "severity": severity
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/local-logs', methods=['GET'])
def api_local_logs():
    """
    GET route returning discovered log files from local Windows system locations.
    """
    try:
        logs = find_local_logs()
        return jsonify(logs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/analyze-local-log', methods=['POST'])
def api_analyze_local_log():
    """
    POST route accepting JSON {"path": "<filepath>"}.
    Reads the file from disk, parses it (.evtx or text), analyzes with AI, and returns results.
    """
    try:
        data = request.get_json(silent=True) or {}
        file_path = data.get('path', '').strip()

        if not file_path:
            return jsonify({"error": "No file path provided."}), 400

        if not os.path.exists(file_path):
            return jsonify({"error": f"File not found: {file_path}"}), 404

        if not os.path.isfile(file_path):
            return jsonify({"error": f"Path is not a regular file: {file_path}"}), 400

        is_evtx = file_path.lower().endswith('.evtx')

        if is_evtx:
            parsed_data = parse_evtx_log(file_path)
            raw_sample = "\n".join(parsed_data.get("suspicious_lines", []) + parsed_data.get("error_lines", []))[:3000]
        else:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    raw_text = f.read()
            except Exception as read_err:
                return jsonify({"error": f"Could not read file: {read_err}"}), 500

            parsed_data = parse_text_log(raw_text)
            raw_sample = raw_text[:3000]

        ai_analysis = analyze_log_with_ai(parsed_data, raw_sample)

        suspicious_count = len(parsed_data.get("suspicious_lines", []))
        error_count = len(parsed_data.get("error_lines", []))

        if suspicious_count >= 10:
            severity = "CRITICAL"
        elif suspicious_count >= 5:
            severity = "HIGH"
        elif suspicious_count >= 1:
            severity = "MEDIUM"
        elif error_count > 0:
            severity = "LOW"
        else:
            severity = "LOW"

        return jsonify({
            "log_type": parsed_data.get("log_type", "unknown"),
            "total_lines": parsed_data.get("total_lines", 0),
            "error_count": error_count,
            "suspicious_count": suspicious_count,
            "suspicious_lines": parsed_data.get("suspicious_lines", []),
            "error_lines": parsed_data.get("error_lines", []),
            "ip_addresses": parsed_data.get("ip_addresses", []),
            "ai_analysis": ai_analysis,
            "severity": severity,
            "file_name": os.path.basename(file_path),
            "file_path": file_path
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/scan/stream')
def api_scan_stream():
    """
    SSE stream endpoint for live terminal scan updates.
    Accepts target_ip query parameter.
    Streams scan progress events line by line formatted as `data: <message>\n\n`.
    """
    target_ip = request.args.get('target_ip', '').strip()
    if not target_ip or not is_valid_ip(target_ip):
        def error_gen():
            yield f"data: Invalid target IP address: {target_ip}\n\n"
        return Response(error_gen(), mimetype='text/event-stream')

    def generate():
        import time
        yield f"data: Initializing scan on {target_ip}...\n\n"
        time.sleep(0.3)

        yield "data: Running Nmap port discovery...\n\n"
        # Run port scan
        scan_results = scan_target(target_ip)
        open_ports = scan_results.get("open_ports", [])
        time.sleep(0.3)

        if open_ports:
            for p in open_ports:
                port = p.get("port", "")
                service = p.get("service_name") or "unknown"
                yield f"data: Discovered open port {port}/tcp ({service})\n\n"
                time.sleep(0.2)
        else:
            yield "data: No open ports discovered on standard probes.\n\n"
            time.sleep(0.2)

        yield "data: Querying NVD vulnerability database...\n\n"
        time.sleep(0.3)

        yield "data: Mapping to MITRE ATT&CK framework...\n\n"
        time.sleep(0.3)

        yield "data: Running Groq AI analysis...\n\n"
        time.sleep(0.3)

        yield "data: Scan complete.\n\n"

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )


@app.route('/api/scan', methods=['POST'])
def api_scan():
    """
    POST route accepting JSON with target_ip field.
    Runs nmap scan, parallel CVE lookup, MITRE technique mapping, AI analysis,
    and returns structured security assessment JSON.
    """
    try:
        data = request.get_json(silent=True) or {}
        target_ip = data.get('target_ip', '').strip()

        # Validate IP address
        if not target_ip or not is_valid_ip(target_ip):
            return jsonify({
                "error": f"'{target_ip}' is not a valid IPv4 or IPv6 address format."
            }), 400

        # 1. Scan target using parser.nmap_scanner.scan_target
        scan_results = scan_target(target_ip)
        scan_error = scan_results.get("error")
        open_ports = scan_results.get("open_ports", [])
        scan_time = scan_results.get("scan_time") or datetime.now(timezone.utc).isoformat()

        # 2. Call get_cves_for_service() from detection.cve_lookup for each open port
        cve_findings = []
        cve_results_map = {}

        def _fetch_cve(port_info):
            service = port_info.get("service_name", "")
            version = port_info.get("service_version", "")
            port = port_info.get("port", "")
            label = f"{service} {port}".strip() or f"port_{port}"
            if service:
                cves = get_cves_for_service(service, version)
            else:
                cves = []
            return label, cves

        if open_ports and not scan_error:
            with ThreadPoolExecutor(max_workers=min(10, len(open_ports))) as executor:
                cve_pairs = list(executor.map(_fetch_cve, open_ports))
                for label, cves in cve_pairs:
                    cve_results_map[label] = cves
                    for cve in cves:
                        cve_findings.append({
                            "cve_id": cve.get("cve_id", "N/A"),
                            "severity": cve.get("severity", "UNKNOWN"),
                            "cvss_score": cve.get("cvss_score", 0.0),
                            "description": cve.get("description", "")
                        })

        # 3. Call map_ports_to_mitre() from detection.mitre_mapper
        mitre_mappings = map_ports_to_mitre(open_ports) if (open_ports and not scan_error) else []

        # 4. Fetch threat intelligence details (AbuseIPDB and Shodan via analyze_ip)
        ai_analysis_from_intel = ""
        try:
            intel = analyze_ip(target_ip)
            isp = intel.get("isp", "Unknown")
            org = intel.get("org", isp)
            country = intel.get("country", "N/A")
            domain = intel.get("domain", "")
            hostnames = intel.get("hostnames", [])
            ai_analysis_from_intel = intel.get("ai_analysis", "")
            # If nmap was unavailable or had an error, fallback to Shodan ports/vulns if available
            if scan_error and intel.get("open_ports"):
                shodan_ports = intel.get("open_ports", [])
                open_ports = [{"port": p, "protocol": "tcp", "service_name": "", "service_version": ""} for p in shodan_ports]
            if scan_error and intel.get("vulnerabilities"):
                for v in intel.get("vulnerabilities", []):
                    cve_findings.append({
                        "cve_id": v,
                        "severity": "UNKNOWN",
                        "cvss_score": 0.0,
                        "description": ""
                    })
        except Exception as intel_err:
            print(f"[api_scan] Threat intel lookup error: {intel_err}")
            isp = "Unknown"
            org = "Unknown"
            country = "N/A"
            domain = ""
            hostnames = []

        # 5. Call analyze_with_ai() from detection.ai_analyzer
        try:
            if not scan_error:
                ai_analysis = analyze_with_ai(scan_results, cve_results_map, mitre_mappings)
            else:
                ai_analysis = ai_analysis_from_intel or analyze_with_ai(
                    {"target_ip": target_ip, "scan_time": scan_time, "open_ports": open_ports},
                    cve_results_map,
                    mitre_mappings
                )
        except Exception as ai_err:
            ai_analysis = f"[AI Analysis Unavailable]\n\nError: {ai_err}"

        # 6. Calculate risk_level based on CVE severity, open ports, and AbuseIPDB
        severities = {cve.get("severity", "").upper() for cve in cve_findings}
        max_cvss = max([cve.get("cvss_score", 0.0) for cve in cve_findings], default=0.0)

        if "CRITICAL" in severities or max_cvss >= 9.0:
            risk_level = "CRITICAL"
        elif "HIGH" in severities or max_cvss >= 7.0 or len(open_ports) >= 10:
            risk_level = "HIGH"
        elif "MEDIUM" in severities or max_cvss >= 4.0 or len(open_ports) >= 5:
            risk_level = "MEDIUM"
        elif len(open_ports) > 0 or "LOW" in severities:
            risk_level = "LOW"
        else:
            risk_level = "LOW"

        # 7. Generate PDF report in screenshots/ directory (for PDF download support)
        try:
            reports_dir = os.path.join(app.root_path, "screenshots")
            os.makedirs(reports_dir, exist_ok=True)
            safe_filename = f"report_{target_ip.replace(':', '_')}.pdf"
            output_pdf_path = os.path.join(reports_dir, safe_filename)

            generate_pdf_report(
                scan_data={
                    "target_ip": target_ip,
                    "scan_time": scan_time,
                    "open_ports": open_ports,
                    "risk_level": risk_level
                },
                cve_data=cve_findings,
                mitre_data=mitre_mappings,
                ai_analysis=ai_analysis,
                output_path=output_pdf_path
            )
        except Exception as pdf_err:
            print(f"[api_scan] PDF generation error: {pdf_err}")

        # 8. Send Telegram alert if threshold met
        scan_payload = {
            "target_ip": target_ip,
            "scan_time": scan_time,
            "risk_level": risk_level,
            "open_ports": open_ports,
            "cve_findings": cve_findings
        }
        try:
            send_telegram_alert(scan_payload)
        except Exception as alert_err:
            print(f"[api_scan] Telegram alert error: {alert_err}")

        # 9. Return the combined result as JSON
        response_payload = {
            "target_ip": target_ip,
            "scan_time": scan_time,
            "risk_level": risk_level,
            "isp": isp,
            "org": org,
            "country": country,
            "domain": domain,
            "hostnames": hostnames,
            "open_ports": open_ports,
            "cve_findings": cve_findings,
            "mitre_mappings": mitre_mappings,
            "ai_analysis": ai_analysis
        }
        if scan_error:
            response_payload["scan_error"] = scan_error

        return jsonify(response_payload)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/scheduler/list', methods=['GET'])
def api_scheduler_list():
    """Returns all scheduled scans as JSON."""
    session = SessionLocal()
    try:
        scans = session.query(ScheduledScan).order_by(ScheduledScan.created_at.desc()).all()
        return jsonify([s.to_dict() for s in scans])
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()


@app.route('/api/scheduler/add', methods=['POST'])
def api_scheduler_add():
    """Accepts target_ip and interval_hours, creates a new ScheduledScan record."""
    data = request.get_json(silent=True) or {}
    target_ip = data.get('target_ip', '').strip()
    try:
        interval_hours = int(data.get('interval_hours', 24))
    except (ValueError, TypeError):
        interval_hours = 24

    if not target_ip or not is_valid_ip(target_ip):
        return jsonify({"error": f"'{target_ip}' is not a valid IPv4 or IPv6 address."}), 400

    session = SessionLocal()
    try:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        # Next run is immediately or calculated from now
        new_scan = ScheduledScan(
            target_ip=target_ip,
            interval_hours=interval_hours,
            last_run=None,
            next_run=now,
            active=1,
            created_at=now
        )
        session.add(new_scan)
        session.commit()
        return jsonify({"status": "success", "scan": new_scan.to_dict()}), 201
    except Exception as e:
        session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()


@app.route('/api/scheduler/remove/<int:scan_id>', methods=['DELETE'])
def api_scheduler_remove(scan_id):
    """Deletes a scheduled scan by ID."""
    session = SessionLocal()
    try:
        scan = session.query(ScheduledScan).filter(ScheduledScan.id == scan_id).first()
        if not scan:
            return jsonify({"error": "Scheduled scan not found."}), 404
        session.delete(scan)
        session.commit()
        return jsonify({"status": "success", "message": f"Scheduled scan {scan_id} removed."})
    except Exception as e:
        session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()


@app.route('/api/false-positive/mark', methods=['POST'])
def api_false_positive_mark():
    """
    POST route accepting JSON {cve_id, service_name}.
    Saves the record to the FalsePositive table.
    """
    data = request.get_json(silent=True) or {}
    cve_id = data.get('cve_id', '').strip()
    service_name = data.get('service_name', '').strip()

    if not cve_id:
        return jsonify({"error": "cve_id is required."}), 400

    session = SessionLocal()
    try:
        existing = session.query(FalsePositive).filter(FalsePositive.cve_id == cve_id).first()
        if existing:
            return jsonify({"status": "exists", "message": f"{cve_id} is already marked as false positive."})

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        fp = FalsePositive(
            cve_id=cve_id,
            service_name=service_name,
            marked_at=now
        )
        session.add(fp)
        session.commit()
        return jsonify({"status": "success", "false_positive": fp.to_dict()}), 201
    except Exception as e:
        session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()


@app.route('/api/false-positive/list', methods=['GET'])
def api_false_positive_list():
    """
    GET route returning all marked false positives as JSON.
    """
    session = SessionLocal()
    try:
        fps = session.query(FalsePositive).order_by(FalsePositive.marked_at.desc()).all()
        return jsonify([fp.to_dict() for fp in fps])
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()


@app.route('/download/report/<ip>')
def download_report(ip):
    """GET route serving the generated PDF report for download."""
    ip = ip.strip()
    if not is_valid_ip(ip):
        flash(f"'{ip}' is not a valid IPv4 or IPv6 address format.", "error")
        return redirect(url_for('home'))

    reports_dir = os.path.join(app.root_path, "screenshots")
    safe_filename = f"report_{ip.replace(':', '_')}.pdf"
    pdf_path = os.path.join(reports_dir, safe_filename)

    if not os.path.exists(pdf_path):
        flash(f"Report PDF for IP '{ip}' does not exist.", "error")
        return redirect(url_for('scanner'))

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=f"Security_Report_{ip}.pdf",
        mimetype="application/pdf"
    )


if __name__ == '__main__':
    start_scheduler()
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port, use_reloader=False)

