import os
import httpx
from groq import Groq

_MODEL = "groq/compound-mini"
_MAX_TOKENS = 1500
_TEMPERATURE = 0.3

_SYSTEM_PROMPT = (
    "You are a friendly cybersecurity assistant explaining scan results "
    "to a non-technical person. Use simple everyday language. Avoid jargon. "
    "Be concise. Maximum 3-4 sentences per section."
)

_USER_PROMPT_TEMPLATE = """
Target IP: {target_ip}
Open Ports: {open_ports}
CVE Findings: {cve_section}
MITRE Mappings: {mitre_section}

Please provide:
1. SUMMARY: What was found in one simple paragraph
2. SHOULD YOU BE WORRIED?: Overall risk in one sentence
3. TOP 3 CONCERNS: Three bullet points maximum, plain English
4. WHAT TO DO NEXT: Maximum 3 simple action steps

Keep total response under 400 words. Use simple language.
"""

def analyze_with_ai(scan_results, cve_results, mitre_mappings):
    api_key = os.environ.get('GROQ_API_KEY', '')
    if not api_key:
        return "[AI Analysis Unavailable]\n\nGROQ_API_KEY not set."

    try:
        open_ports = scan_results.get('open_ports', [])
        ports_text = ', '.join([str(p.get('port','')) + '/' + str(p.get('service_name','')) for p in open_ports]) if open_ports else 'None found'

        if isinstance(cve_results, list):
            cves_text = ', '.join([c.get('cve_id','') for c in cve_results[:5]]) if cve_results else 'None'
        elif isinstance(cve_results, dict):
            all_cves = []
            for v in cve_results.values():
                if isinstance(v, list):
                    all_cves.extend([c.get('cve_id','') for c in v[:3]])
            cves_text = ', '.join(all_cves) if all_cves else 'None'
        else:
            cves_text = 'None'

        mitre_text = ', '.join([m.get('technique_id','') + ' ' + m.get('technique_name','') for m in mitre_mappings[:5]]) if mitre_mappings else 'None'

        prompt = _USER_PROMPT_TEMPLATE.format(
            target_ip=scan_results.get('target_ip', 'Unknown'),
            open_ports=ports_text,
            cve_section=cves_text,
            mitre_section=mitre_text
        )

        http_client = httpx.Client(
            timeout=30.0,
            transport=httpx.HTTPTransport(retries=1)
        )
        client = Groq(api_key=api_key, http_client=http_client)
        response = client.chat.completions.create(
            model=_MODEL,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            temperature=_TEMPERATURE,
            max_tokens=_MAX_TOKENS,
        )
        return response.choices[0].message.content

    except Exception as e:
        return f"[AI Analysis Unavailable]\n\nUnexpected error: {str(e)}"