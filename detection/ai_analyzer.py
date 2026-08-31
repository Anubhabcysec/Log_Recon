"""
detection/ai_analyzer.py
"""

from config import Config

_MODEL = "groq/compound-mini"
_MAX_TOKENS = 2048
_TEMPERATURE = 0.3

_SYSTEM_PROMPT = (
    "You are a friendly cybersecurity assistant explaining scan results to a non-technical person. "
    "Use simple everyday language. Avoid jargon. If you must use a technical term, explain it in brackets immediately after. "
    "Be concise. Maximum 3-4 sentences per section. Think of explaining to a smart friend who knows nothing about cybersecurity."
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

Please produce a clear, non-technical security summary covering ALL of the following
sections. Use markdown headings:

## What This Scan Found
One paragraph, plain English, what was discovered on this device/IP.

## Should You Be Worried?
Overall risk in one sentence. Use simple words like "This looks safe", "There are some concerns", or "This needs urgent attention".

## The 3 Most Important Things
Three bullet points maximum. Each one: what the problem is + why it matters to a normal person + one simple thing they can do about it.

## What To Do Next
Maximum 3 simple action steps. Written like texting a friend instructions, not a technical manual.

Keep total response under 400 words.
"""


def _build_open_ports_table(open_ports: list) -> str:
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


def _build_cve_section(cve_results) -> str:
    if not cve_results:
        return "  No CVE data available."
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
                short = desc[:200] + ("..." if len(desc) > 200 else "")
                lines.append(f"      {short}")
        lines.append("")
    return "\n".join(lines).rstrip()


def _build_mitre_section(mitre_mappings: list) -> str:
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
    return _USER_PROMPT_TEMPLATE.format(
        target_ip=scan_results.get("target_ip", "Unknown"),
        scan_time=scan_results.get("scan_time", "Unknown"),
        open_ports_table=_build_open_ports_table(scan_results.get("open_ports", [])),
        cve_section=_build_cve_section(cve_results),
        mitre_section=_build_mitre_section(mitre_mappings),
    )


def analyze_with_ai(scan_results: dict, cve_results, mitre_mappings: list) -> str:
    api_key = getattr(Config, "GROQ_API_KEY", "")
    if not api_key:
        return (
            "[AI Analysis Unavailable]\n\n"
            "GROQ_API_KEY is not set in your environment.\n"
            "Add it to your .env file: GROQ_API_KEY=your_key_here\n"
            "Get a free key at https://console.groq.com"
        )
    try:    
        import httpx
        from groq import Groq, APIError, APIConnectionError, RateLimitError
    except ImportError:
        return "[AI Analysis Unavailable]\n\nRun: pip install groq"

    user_prompt = _build_prompt(scan_results, cve_results, mitre_mappings)
    try:
        http_client = httpx.Client()
        client = Groq(api_key=api_key, http_client=http_client)
        
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
        return "[AI Analysis Unavailable]\n\nGroq rate limit exceeded. Wait a moment and try again."
    except APIConnectionError as exc:
        return f"[AI Analysis Unavailable]\n\nCould not connect to Groq API: {exc}"
    except APIError as exc:
        return f"[AI Analysis Unavailable]\n\nGroq API returned an error (status {exc.status_code}): {exc.message}"
    except Exception as exc:
        return f"[AI Analysis Unavailable]\n\nUnexpected error: {exc}"