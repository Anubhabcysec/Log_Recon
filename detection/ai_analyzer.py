"""
detection/ai_analyzer.py
------------------------
Uses the Groq API (llama-3.1-8b-instant) to perform an AI-driven security
analysis of nmap scan results, discovered CVEs, and MITRE ATT&CK mappings.

Functions:
    analyze_with_ai(scan_results, cve_results, mitre_mappings)
        -- Send enriched scan data to the LLM and return a structured
           security assessment as a plain string.

Usage:
    from detection.ai_analyzer import analyze_with_ai

    analysis = analyze_with_ai(scan_results, cve_results, mitre_mappings)
    print(analysis)
"""

import json
from config import Config

# ---------------------------------------------------------------------------
# Model configuration
# ---------------------------------------------------------------------------
_MODEL = "llama-3.1-8b-instant"
_MAX_TOKENS = 2048
_TEMPERATURE = 0.3        # Lower = more deterministic / analytical tone

# ---------------------------------------------------------------------------
# Prompt template
# ---------------------------------------------------------------------------
_SYSTEM_PROMPT = (
    "You are an expert cybersecurity analyst specialising in incident response "
    "and vulnerability assessment. Your job is to analyse network scan results, "
    "CVE data, and MITRE ATT&CK technique mappings, then produce a clear, "
    "actionable security report. Be concise, prioritise the most impactful "
    "findings, and always give specific, practical remediation advice."
)

_USER_PROMPT_TEMPLATE = """\
## Security Scan Data for Analysis

### 1. Nmap Scan Results
Target IP : {target_ip}
Scan Time : {scan_time}

Open Ports:
{open_ports_table}

### 2. CVE Findings
{cve_section}

### 3. MITRE ATT&CK Technique Mappings
{mitre_section}

---

Please produce a structured security assessment covering ALL of the following
sections. Use markdown headings:

## Risk Overview
Give an overall risk rating (CRITICAL / HIGH / MEDIUM / LOW) with a 2-3
sentence executive summary.

## Prioritised Vulnerabilities
Rank the identified vulnerabilities by exploitability and potential impact.
For each, state why it is dangerous and how easy it is to exploit.

## Critical Attack Vectors
Identify the most likely paths an attacker would take to compromise this host.
Reference the relevant MITRE techniques.

## Immediate Remediation Steps
List specific, actionable steps the defender should take right now (ordered by
priority). Include commands or configuration changes where applicable.

## Long-Term Hardening Recommendations
Suggest broader security improvements beyond the immediate fixes.
"""

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_open_ports_table(open_ports: list) -> str:
    """Format open_ports list as a human-readable text table."""
    if not open_ports:
        return "  (no open ports detected)"

    lines = ["  Port   Proto  State          Service          Version"]
    lines.append("  " + "-" * 68)
    for p in open_ports:
        lines.append(
            f"  {p.get('port', '?'):<7}"
            f"{p.get('protocol', ''):<7}"
            f"{p.get('state', ''):<15}"
            f"{p.get('service_name', ''):<17}"
            f"{p.get('service_version', '')}"
        )
    return "\n".join(lines)


def _build_cve_section(cve_results: dict) -> str:
    """
    Format CVE results dict as readable text.

    cve_results is expected to be a dict keyed by service label with lists
    of CVE dicts, e.g.:
        {"ssh 8.9": [{"cve_id": "CVE-...", "cvss_score": 9.1, ...}, ...]}

    Also accepts a plain list of CVE dicts for a single service.
    """
    if not cve_results:
        return "  No CVE data available."

    # Support both dict-of-lists and plain list
    if isinstance(cve_results, list):
        cve_results = {"findings": cve_results}

    lines = []
    for service_label, cves in cve_results.items():
        lines.append(f"  Service: {service_label}")
        if not cves:
            lines.append("    No CVEs found.")
            continue
        for cve in cves:
            lines.append(
                f"    [{cve.get('severity', 'N/A')}] "
                f"{cve.get('cve_id', 'N/A')} "
                f"(CVSS {cve.get('cvss_score', 'N/A')}) "
                f"— Published: {cve.get('published_date', 'N/A')}"
            )
            desc = cve.get("description", "")
            if desc:
                # Truncate long descriptions for prompt efficiency
                short = desc[:200] + ("..." if len(desc) > 200 else "")
                lines.append(f"      {short}")
        lines.append("")
    return "\n".join(lines).rstrip()


def _build_mitre_section(mitre_mappings: list) -> str:
    """Format MITRE mappings list as readable text."""
    if not mitre_mappings:
        return "  No MITRE mappings available."

    lines = ["  Port   Technique ID   Tactic                  Technique Name"]
    lines.append("  " + "-" * 72)
    for m in mitre_mappings:
        lines.append(
            f"  {m.get('port', '?'):<7}"
            f"{m.get('technique_id', ''):<15}"
            f"{m.get('tactic', ''):<24}"
            f"{m.get('technique_name', '')}"
        )
    return "\n".join(lines)


def _build_prompt(scan_results: dict, cve_results, mitre_mappings: list) -> str:
    """Assemble the full user prompt from the three data sources."""
    return _USER_PROMPT_TEMPLATE.format(
        target_ip=scan_results.get("target_ip", "Unknown"),
        scan_time=scan_results.get("scan_time", "Unknown"),
        open_ports_table=_build_open_ports_table(scan_results.get("open_ports", [])),
        cve_section=_build_cve_section(cve_results),
        mitre_section=_build_mitre_section(mitre_mappings),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_with_ai(
    scan_results: dict,
    cve_results,
    mitre_mappings: list,
) -> str:
    """
    Send scan data to the Groq LLM and return an AI-generated security report.

    Args:
        scan_results:   Dict returned by ``parser.nmap_scanner.scan_target()``.
                        Must contain at least ``target_ip`` and ``open_ports``.
        cve_results:    CVE data — either a dict keyed by service label (each
                        value a list of CVE dicts from ``detection.cve_lookup``),
                        or a plain list of CVE dicts for a single service.
        mitre_mappings: List of dicts returned by
                        ``detection.mitre_mapper.map_ports_to_mitre()``.

    Returns:
        A markdown-formatted string containing the AI security assessment, or
        a plain-text fallback message if the API is unavailable or misconfigured.
    """
    # ------------------------------------------------------------------
    # Validate API key
    # ------------------------------------------------------------------
    api_key = getattr(Config, "GROQ_API_KEY", "")
    if not api_key:
        return (
            "[AI Analysis Unavailable]\n\n"
            "GROQ_API_KEY is not set in your environment. "
            "Add it to your .env file:\n\n"
            "    GROQ_API_KEY=your_key_here\n\n"
            "Get a free key at https://console.groq.com"
        )

    # ------------------------------------------------------------------
    # Import groq (defer so missing install gives a clean message)
    # ------------------------------------------------------------------
    try:
        from groq import Groq, APIError, APIConnectionError, RateLimitError
    except ImportError:
        return (
            "[AI Analysis Unavailable]\n\n"
            "The 'groq' package is not installed. "
            "Run: pip install groq"
        )

    # ------------------------------------------------------------------
    # Build prompt and call the API
    # ------------------------------------------------------------------
    user_prompt = _build_prompt(scan_results, cve_results, mitre_mappings)

    try:
        client = Groq(api_key=api_key)
        chat_completion = client.chat.completions.create(
            model=_MODEL,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=_TEMPERATURE,
            max_tokens=_MAX_TOKENS,
        )
        return chat_completion.choices[0].message.content

    except RateLimitError:
        return (
            "[AI Analysis Unavailable]\n\n"
            "Groq API rate limit exceeded. Please wait a moment and try again."
        )
    except APIConnectionError as exc:
        return (
            f"[AI Analysis Unavailable]\n\n"
            f"Could not connect to the Groq API: {exc}\n"
            "Check your internet connection and try again."
        )
    except APIError as exc:
        return (
            f"[AI Analysis Unavailable]\n\n"
            f"Groq API returned an error (status {exc.status_code}): {exc.message}"
        )
    except Exception as exc:  # noqa: BLE001
        return (
            f"[AI Analysis Unavailable]\n\n"
            f"An unexpected error occurred while contacting the AI: {exc}"
        )