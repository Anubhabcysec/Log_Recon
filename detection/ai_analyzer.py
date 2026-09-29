import os

def analyze_with_ai(scan_results, cve_results, mitre_mappings):
    api_key = os.environ.get('GROQ_API_KEY', '')
    if not api_key:
        return "AI Analysis Unavailable: GROQ_API_KEY not set."

    try:
        import httpx
        from groq import Groq

        open_ports = scan_results.get('open_ports', [])
        ports_text = ', '.join([
            str(p.get('port','')) + '/' + str(p.get('service_name',''))
            for p in open_ports
        ]) if open_ports else 'None found'

        if isinstance(cve_results, list):
            cves_text = ', '.join([c.get('cve_id','') for c in cve_results[:5]]) or 'None'
        elif isinstance(cve_results, dict):
            all_cves = []
            for v in cve_results.values():
                if isinstance(v, list):
                    all_cves.extend([c.get('cve_id','') for c in v[:3]])
            cves_text = ', '.join(all_cves) or 'None'
        else:
            cves_text = 'None'

        mitre_text = ', '.join([
            m.get('technique_id','') + ' ' + m.get('technique_name','')
            for m in mitre_mappings[:5]
        ]) if mitre_mappings else 'None'

        prompt = f"""
Target IP: {scan_results.get('target_ip', 'Unknown')}
Open Ports: {ports_text}
CVEs Found: {cves_text}
MITRE Techniques: {mitre_text}

Explain this scan to a non-technical person in simple English:
1. SUMMARY: What was found (one paragraph)
2. RISK LEVEL: Is this safe or dangerous? (one sentence)
3. TOP CONCERNS: Up to 3 bullet points with citations
4. WHAT TO DO: Up to 3 simple action steps with citations

You must cite specific evidence for every claim you make. Format: claim [EVIDENCE: source]. For CVEs always mention the CVE ID. For ports always mention the port number. For log activity always quote the specific log line. Never make a claim without citing where it came from. Keep total response under 400 words. No jargon.
"""

        transport = httpx.HTTPTransport(retries=1)
        http_client = httpx.Client(timeout=30.0, transport=transport)
        client = Groq(api_key=api_key, http_client=http_client)

        response = client.chat.completions.create(
            model="qwen/qwen3.8-27b",
            messages=[
                {
                    "role": "system",
                    "content": "You are a friendly cybersecurity assistant. Explain things simply. You must cite specific evidence for every claim you make. Format: claim [EVIDENCE: source]. For CVEs always mention the CVE ID. For ports always mention the port number. For log activity always quote the specific log line. Never make a claim without citing where it came from. Keep total response under 400 words."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.3,
            max_tokens=1000,
        )
        return response.choices[0].message.content

    except Exception as e:
        return f"AI Analysis Unavailable: {str(e)}"
