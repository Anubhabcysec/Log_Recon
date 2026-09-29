"""
detection/correlator.py
-----------------------
Correlates scan results (open ports, CVEs, services) with raw log text and
AbuseIPDB abuse data to produce per-port risk verdicts and a structured
summary.

Usage:
    from detection.correlator import correlate
    result = correlate(scan_result, log_text, abuse_data)
"""

import json
import logging
import os
from typing import Optional

from sqlalchemy.orm import sessionmaker
from config import Config
from database.models import CorrelatedFinding, create_tables

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Well-known port -> service name mapping used as a fallback when the caller
# does not supply service information.
# ---------------------------------------------------------------------------
_PORT_SERVICE_MAP: dict = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    27017: "mongodb",
}

# Risk verdict ordering (higher index = higher severity)
_VERDICT_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _service_for_port(port: int, services_map: dict) -> str:
    """Return service name for *port*, checking caller-supplied map first."""
    name = services_map.get(port) or _PORT_SERVICE_MAP.get(port, "")
    return name.lower().strip() if name else ""


def _search_log_lines(log_text: str, terms: list, max_hits: int = 5) -> list:
    """
    Return up to *max_hits* log lines (stripped) that contain ANY of *terms*.
    Matching is case-insensitive.  Empty / whitespace-only terms are skipped.
    """
    if not log_text or not terms:
        return []

    clean_terms = [t.strip().lower() for t in terms if t and t.strip()]
    if not clean_terms:
        return []

    hits = []
    for line in log_text.splitlines():
        line_lower = line.lower()
        if any(term in line_lower for term in clean_terms):
            stripped = line.strip()
            if stripped:
                hits.append(stripped)
                if len(hits) >= max_hits:
                    break
    return hits


def _determine_verdict(has_cve: bool, has_log: bool, has_abuse: bool) -> str:
    """
    Risk verdict matrix:
        All three present        -> CRITICAL
        Any two of three         -> HIGH
        Exactly one present      -> MEDIUM
        None present             -> LOW
    """
    score = sum([has_cve, has_log, has_abuse])
    if score == 3:
        return "CRITICAL"
    if score == 2:
        return "HIGH"
    if score == 1:
        return "MEDIUM"
    return "LOW"


def _overall_risk(verdicts: list) -> str:
    """Return the highest risk verdict seen across all findings."""
    if not verdicts:
        return "LOW"
    return max(verdicts, key=lambda v: _VERDICT_ORDER.index(v) if v in _VERDICT_ORDER else -1)


def _extract_ports_info(scan_result: dict) -> list:
    """
    Normalise port information from scan_result into a list of dicts with keys:
        port (int), service (str), version (str)

    Accepts several common shapes:
      - {"open_ports": [22, 80, ...]}                          plain int list
      - {"open_ports": [{"port": 22, "service": "ssh"}, ...]} dict list
      - {"ports": [...]}                                       alternate key
    """
    raw_ports = scan_result.get("open_ports") or scan_result.get("ports") or []

    # Handle JSON string
    if isinstance(raw_ports, str):
        try:
            raw_ports = json.loads(raw_ports)
        except (ValueError, TypeError):
            raw_ports = []

    normalised = []
    for entry in raw_ports:
        if isinstance(entry, int):
            normalised.append({"port": entry, "service": "", "version": ""})
        elif isinstance(entry, dict):
            port_num = entry.get("port") or entry.get("port_number") or 0
            try:
                port_num = int(port_num)
            except (TypeError, ValueError):
                port_num = 0
            normalised.append({
                "port": port_num,
                "service": (entry.get("service_name") or entry.get("service") or "").lower(),
                "version": (entry.get("service_version") or entry.get("version") or ""),
                "cve_id": entry.get("cve_id"),  # pass through per-port CVE if present
            })

    return normalised


def _extract_vulnerabilities(scan_result: dict) -> list:
    """
    Return a flat list of CVE ID strings from scan_result.
    Accepts plain lists of strings and lists of dicts with a 'cve_id' key.
    """
    raw_vulns = scan_result.get("vulnerabilities") or scan_result.get("cves") or []

    if isinstance(raw_vulns, str):
        try:
            raw_vulns = json.loads(raw_vulns)
        except (ValueError, TypeError):
            raw_vulns = []

    cve_ids = []
    for v in raw_vulns:
        if isinstance(v, str):
            cve_ids.append(v)
        elif isinstance(v, dict):
            cve_id = v.get("cve_id") or v.get("id") or ""
            if cve_id:
                cve_ids.append(cve_id)
    return cve_ids


def _build_services_map(ports_info: list) -> dict:
    """Build port -> service lookup from normalised ports_info."""
    return {
        entry["port"]: entry["service"]
        for entry in ports_info
        if entry["port"] and entry["service"]
    }


def _match_cve_to_service(service: str, cve_ids: list) -> Optional[str]:
    """
    Lightweight heuristic: return the first CVE in the list when a service
    name is present. Production callers should supply per-service CVE data
    from cve_lookup.get_cves_for_service() for accurate matching.
    """
    if not service or not cve_ids:
        return None
    return cve_ids[0] if cve_ids else None


def _save_findings(ip: str, scan_id: Optional[int], findings: list) -> None:
    """Persist each correlated finding to the CorrelatedFinding table."""
    try:
        engine = create_tables()
        Session = sessionmaker(bind=engine)
        session = Session()
        try:
            for finding in findings:
                record = CorrelatedFinding(
                    ip_address=ip,
                    scan_id=scan_id,
                    port=finding.get("port"),
                    service=finding.get("service") or None,
                    cve_id=finding.get("cve_id") or None,
                    log_evidence=json.dumps(finding.get("log_evidence", [])),
                    abuse_reports_count=finding.get("abuse_reports", 0),
                    risk_verdict=finding.get("risk_verdict", "LOW"),
                )
                session.add(record)
            session.commit()
            logger.info("[correlator] Saved %d finding(s) for %s", len(findings), ip)
        except Exception as db_err:
            session.rollback()
            logger.error("[correlator] DB save failed: %s", db_err)
        finally:
            session.close()
    except Exception as eng_err:
        logger.error("[correlator] Could not open DB engine: %s", eng_err)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _generate_ai_verdict(ip: str, overall_risk: str, summary_stats: dict, findings: list) -> str:
    """Generate 3-4 plain English sentences summarizing the correlation result using Groq."""
    api_key = os.environ.get("GROQ_API_KEY") or getattr(Config, "GROQ_API_KEY", "")
    if not api_key:
        return (
            f"Analysis for {ip or 'target host'} shows an overall {overall_risk} risk posture. "
            f"A total of {summary_stats.get('total_ports', 0)} open ports and {summary_stats.get('total_cves', 0)} known CVE vulnerabilities were identified. "
            f"Cross-referencing against provided log text matched {summary_stats.get('total_log_matches', 0)} log entries alongside {summary_stats.get('total_abuse_reports', 0)} external abuse reports. "
            "Immediate triage and network containment should focus on exposed services showing active log activity."
        )

    try:
        import httpx
        from groq import Groq

        # Summarize active findings for prompt
        active_findings_summary = []
        for f in findings:
            if f.get("port") is not None:
                active_findings_summary.append(
                    f"Port {f['port']} ({f.get('service') or 'unknown'}): CVE={f.get('cve_id') or 'none'}, "
                    f"LogHits={len(f.get('log_evidence', []))}, AbuseReports={f.get('abuse_reports', 0)}, Verdict={f.get('risk_verdict')}"
                )

        prompt = (
            f"Target IP: {ip}\n"
            f"Overall Risk: {overall_risk}\n"
            f"Total Open Ports: {summary_stats.get('total_ports', 0)}\n"
            f"Total CVEs Found: {summary_stats.get('total_cves', 0)}\n"
            f"Total Log Matches: {summary_stats.get('total_log_matches', 0)}\n"
            f"Total Abuse Reports: {summary_stats.get('total_abuse_reports', 0)}\n"
            f"Port Findings: {'; '.join(active_findings_summary[:6]) if active_findings_summary else 'None'}\n\n"
            "Provide an executive security verdict in exactly 3-4 plain English sentences. "
            "Explain what the correlation reveals about active attacks or exposure, highlight the most critical concern, "
            "and suggest the primary defensive action to take. Avoid jargon."
        )

        transport = httpx.HTTPTransport(retries=1)
        http_client = httpx.Client(timeout=15.0, transport=transport)
        client = Groq(api_key=api_key, http_client=http_client)

        chat_completion = client.chat.completions.create(
            model="qwen/qwen3.8-27b",
            messages=[
                {
                    "role": "system",
                    "content": "You are a senior incident response analyst summarizing threat correlation findings."
                },
                {"role": "user", "content": prompt}
            ],
            max_tokens=300,
            temperature=0.2
        )
        verdict_text = chat_completion.choices[0].message.content.strip()
        return verdict_text if verdict_text else "Correlation complete. Review individual findings for port and log activity."
    except Exception as e:
        logger.warning("[correlator] AI verdict generation failed: %s", e)
        return (
            f"Target {ip or 'host'} has been assessed with an overall risk of {overall_risk}. "
            f"Identified {summary_stats.get('total_ports', 0)} open ports, {summary_stats.get('total_cves', 0)} CVEs, and {summary_stats.get('total_log_matches', 0)} matching log lines. "
            f"External threat intelligence lists {summary_stats.get('total_abuse_reports', 0)} abuse reports for this target. "
            "Recommend reviewing high-risk ports and blocking hostile connection attempts."
        )


def correlate(
    scan_result: dict,
    log_text: str,
    abuse_data: dict,
    scan_id: Optional[int] = None,
) -> dict:
    """
    Correlate scan results with log evidence and AbuseIPDB data.
    """
    # ------------------------------------------------------------------
    # 1. Extract target IP
    # ------------------------------------------------------------------
    ip: str = (
        scan_result.get("ip")
        or scan_result.get("target_ip")
        or abuse_data.get("ip")
        or ""
    ).strip()

    # ------------------------------------------------------------------
    # 2. Normalise ports and vulnerabilities from scan_result
    # ------------------------------------------------------------------
    ports_info: list = _extract_ports_info(scan_result)
    cve_ids: list = _extract_vulnerabilities(scan_result)
    services_map: dict = _build_services_map(ports_info)

    # ------------------------------------------------------------------
    # 3. Resolve abuse report count from various dict shapes
    # ------------------------------------------------------------------
    abuse_inner = abuse_data.get("data", abuse_data)   # unwrap nested response
    abuse_reports_count: int = int(
        abuse_inner.get("totalReports")
        or abuse_inner.get("total_reports")
        or abuse_data.get("totalReports")
        or abuse_data.get("total_reports")
        or 0
    )
    has_abuse_global = abuse_reports_count > 0

    # ------------------------------------------------------------------
    # 4. Also search for log lines mentioning the target IP directly
    # ------------------------------------------------------------------
    ip_log_hits = _search_log_lines(log_text, [ip]) if ip else []

    # ------------------------------------------------------------------
    # 5. Build per-port correlated findings
    # ------------------------------------------------------------------
    correlated_findings: list = []
    all_verdicts: list = []
    total_log_matches = 0

    for port_info in ports_info:
        port: int = port_info["port"]
        service: str = port_info.get("service") or _service_for_port(port, services_map)
        version: str = port_info.get("version", "")

        # Search log for port number, service name, and version string
        search_terms = [str(port)]
        if service:
            search_terms.append(service)
        if version:
            search_terms.append(version)

        log_hits: list = _search_log_lines(log_text, search_terms, max_hits=5)
        total_log_matches += len(log_hits)

        # CVE: prefer per-port value, fall back to heuristic from flat list
        cve_id: Optional[str] = port_info.get("cve_id") or _match_cve_to_service(service, cve_ids)
        cve_sev: str = port_info.get("cve_severity") or "CRITICAL" if cve_id else ""

        # Verdict
        verdict = _determine_verdict(
            has_cve=bool(cve_id),
            has_log=bool(log_hits),
            has_abuse=has_abuse_global,
        )
        all_verdicts.append(verdict)

        correlated_findings.append({
            "port": port,
            "service": service,
            "cve_id": cve_id,
            "cve_severity": cve_sev,
            "log_evidence": log_hits,
            "abuse_reports": abuse_reports_count,
            "risk_verdict": verdict,
        })

    # ------------------------------------------------------------------
    # 6. IP-level finding: add when the target IP appears in logs but the
    #    same lines are not already captured by a port-level finding.
    # ------------------------------------------------------------------
    if ip_log_hits:
        captured_lines = {
            line
            for f in correlated_findings
            for line in f["log_evidence"]
        }
        novel_ip_hits = [l for l in ip_log_hits if l not in captured_lines]
        if novel_ip_hits:
            verdict = _determine_verdict(
                has_cve=bool(cve_ids),
                has_log=True,
                has_abuse=has_abuse_global,
            )
            all_verdicts.append(verdict)
            total_log_matches += len(novel_ip_hits)
            correlated_findings.append({
                "port": None,
                "service": "ip-reference",
                "cve_id": cve_ids[0] if cve_ids else None,
                "cve_severity": "CRITICAL" if cve_ids else "",
                "log_evidence": novel_ip_hits,
                "abuse_reports": abuse_reports_count,
                "risk_verdict": verdict,
            })

    # ------------------------------------------------------------------
    # 7. Overall risk and summary stats
    # ------------------------------------------------------------------
    overall_risk = _overall_risk(all_verdicts)

    summary_stats = {
        "total_ports": len(ports_info),
        "total_cves": len(cve_ids),
        "total_log_matches": total_log_matches,
        "total_abuse_reports": abuse_reports_count,
    }

    # ------------------------------------------------------------------
    # 8. AI Verdict
    # ------------------------------------------------------------------
    ai_verdict = _generate_ai_verdict(ip, overall_risk, summary_stats, correlated_findings)

    # ------------------------------------------------------------------
    # 9. Persist findings to the database
    # ------------------------------------------------------------------
    _save_findings(ip, scan_id, correlated_findings)

    return {
        "ip": ip,
        "correlated_findings": correlated_findings,
        "overall_risk": overall_risk,
        "summary_stats": summary_stats,
        "ai_verdict": ai_verdict,
    }
