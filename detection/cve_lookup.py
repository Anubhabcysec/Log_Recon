"""
detection/cve_lookup.py
-----------------------
Queries the NIST NVD API v2.0 for CVEs matching a given service name and
version string. Returns the top 5 most recent results enriched with CVSS
score, severity label, and a human-readable description.

Usage:
    from detection.cve_lookup import get_cves_for_service
    cves = get_cves_for_service("openssh", "8.9")
"""

import requests
from datetime import datetime
from config import Config

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RESULTS = 5
REQUEST_TIMEOUT = 10  # seconds


def _get_cvss_info(cve_item: dict) -> tuple:
    """
    Extract CVSS base score and severity from a CVE item dict.
    Prefers CVSSv3.1 > CVSSv3.0 > CVSSv2 in that order.

    Returns:
        (score, severity) - score is a float, severity is a string label.
    """
    metrics = cve_item.get("metrics", {})

    # Try CVSSv3.1 first, then CVSSv3.0
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore", 0.0)
            severity = data.get("baseSeverity", "")
            if score:
                return float(score), _normalise_severity(score, severity)

    # Fall back to CVSSv2
    entries = metrics.get("cvssMetricV2", [])
    if entries:
        data = entries[0].get("cvssData", {})
        score = data.get("baseScore", 0.0)
        return float(score), _normalise_severity(score)

    return 0.0, "UNKNOWN"


def _normalise_severity(score: float, label: str = "") -> str:
    """
    Derive a consistent CRITICAL/HIGH/MEDIUM/LOW label.
    Uses the NVD-supplied label when available, otherwise derives from score.
    """
    if label and label.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return label.upper()

    # CVSS v3 thresholds
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    return "UNKNOWN"


def _format_published(date_str: str) -> str:
    """Convert NVD ISO-8601 timestamp to a readable date string (YYYY-MM-DD)."""
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d")
    except (ValueError, AttributeError):
        return date_str


def _get_false_positive_ids() -> set:
    """Fetch all marked false positive CVE IDs from the database."""
    try:
        from database.models import FalsePositive, create_tables
        from sqlalchemy.orm import sessionmaker

        engine = create_tables()
        Session = sessionmaker(bind=engine)
        session = Session()
        try:
            fps = session.query(FalsePositive.cve_id).all()
            return {fp[0] for fp in fps if fp[0]}
        finally:
            session.close()
    except Exception as e:
        print(f"[cve_lookup] Could not query false positives: {e}")
        return set()


def _fetch_epss(cve_id: str) -> tuple:
    """
    Query FIRST.org EPSS API for a given CVE ID.
    Returns:
        (epss_score, epss_percentile) - both float or None if failed.
    """
    if not cve_id or cve_id == "N/A":
        return None, None
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            items = data.get("data", [])
            if items:
                item = items[0]
                score = float(item.get("epss")) if item.get("epss") is not None else None
                percentile = float(item.get("percentile")) if item.get("percentile") is not None else None
                return score, percentile
    except Exception as exc:
        print(f"[cve_lookup] EPSS lookup failed for {cve_id}: {exc}")
    return None, None


def get_cves_for_service(service_name: str, version: str) -> list:
    """
    Query the NVD API v2.0 for CVEs related to a service and version.
    Filters out any false positive marked CVEs and enriches each result with EPSS score and percentile.

    Args:
        service_name: The name of the service/software (e.g. "openssh", "nginx").
        version:      The version string (e.g. "8.9", "1.23.1").

    Returns:
        A list of up to 5 dicts (most recent first), each containing:
            - cve_id          (str)   e.g. "CVE-2023-12345"
            - description     (str)   English description of the vulnerability
            - cvss_score      (float) CVSS base score (0.0 if unavailable)
            - severity        (str)   "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN"
            - published_date  (str)   "YYYY-MM-DD"
            - epss_score      (float | None) EPSS exploit probability score
            - epss_percentile (float | None) EPSS percentile ranking
        Returns an empty list on any error.
    """
    keyword = f"{service_name} {version}".strip()

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": MAX_RESULTS,
        "startIndex": 0,
    }

    headers = {"Accept": "application/json"}

    # Attach API key if configured - raises rate limit from 5 req/30s to 50
    api_key = getattr(Config, "NVD_API_KEY", "")
    if api_key:
        headers["apiKey"] = api_key

    try:
        response = requests.get(
            NVD_API_URL,
            params=params,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as exc:
        print(f"[cve_lookup] NVD API request failed: {exc}")
        return []
    except ValueError as exc:
        print(f"[cve_lookup] Failed to parse NVD API response: {exc}")
        return []

    vulnerabilities = data.get("vulnerabilities", [])
    false_positives = _get_false_positive_ids()
    results = []

    for entry in vulnerabilities[:MAX_RESULTS]:
        cve_item = entry.get("cve", {})

        cve_id = cve_item.get("id", "N/A")
        # Filter out false positives
        if cve_id in false_positives:
            continue

        published_date = _format_published(cve_item.get("published", ""))

        # Extract English description (fall back to first available)
        descriptions = cve_item.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "No description available.")

        cvss_score, severity = _get_cvss_info(cve_item)
        epss_score, epss_percentile = _fetch_epss(cve_id)

        results.append(
            {
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "severity": severity,
                "published_date": published_date,
                "epss_score": epss_score,
                "epss_percentile": epss_percentile,
            }
        )

    return results

