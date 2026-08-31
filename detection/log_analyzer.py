"""
detection/log_analyzer.py
-------------------------
Performs AI-assisted log analysis using the Groq API (groq/compound-mini).
Translates technical log events and detected anomalies into clear,
plain-English summaries for non-experts and defenders.
"""

import os
from config import Config

_MODEL = "groq/compound-mini"
_MAX_TOKENS = 2048
_TEMPERATURE = 0.3

_SYSTEM_PROMPT = (
    "You are an expert cybersecurity analyst who excels at translating complex "
    "technical and security log data into simple, clear, jargon-free explanations "
    "for general readers and defenders."
)

_USER_PROMPT_TEMPLATE = """\
You are a cybersecurity analyst. Analyze this log file and explain it in simple, clear English that anyone can understand. The person reading this is not a security expert.

Log type: {log_type}
Total lines: {total_lines}

Sample of the log:
{raw_sample}

Suspicious lines found:
{suspicious_lines}

Please provide:
1. SUMMARY: What is this log file about in one paragraph, plain English
2. WHAT HAPPENED: List the 3-5 most important things that happened, explained simply
3. URGENT ALERTS: Anything that needs immediate attention (use NONE if nothing serious)
4. SUSPICIOUS ACTIVITY: Any signs of attacks, unauthorized access, or unusual behavior
5. RECOMMENDED ACTIONS: Simple steps the user should take

Use simple language. Avoid jargon. Explain technical terms when you must use them.
"""


def analyze_log_with_ai(parsed_log: dict, raw_sample: str) -> str:
    """
    Analyzes log data using the Groq AI API and returns a plain English assessment.

    Args:
        parsed_log: Dictionary returned by parser.log_parser (containing log_type,
                    total_lines, suspicious_lines, error_lines, etc.).
        raw_sample: String with the first ~3000 characters of the raw log file.

    Returns:
        A formatted string with the AI analysis or an informative fallback message on error.
    """
    # 1. Load GROQ_API_KEY from environment / Config
    api_key = os.environ.get("GROQ_API_KEY") or getattr(Config, "GROQ_API_KEY", "")
    if not api_key:
        return (
            "[AI Analysis Unavailable]\n\n"
            "GROQ_API_KEY is not set in your environment or .env file.\n"
            "Please configure GROQ_API_KEY to enable AI log analysis."
        )

    # 2. Try importing the Groq library
    try:
        from groq import Groq, APIError, APIConnectionError, RateLimitError
    except ImportError:
        return (
            "[AI Analysis Unavailable]\n\n"
            "The 'groq' package is not installed. Please run: pip install groq"
        )

    # 3. Format inputs for prompt
    log_type = parsed_log.get("log_type", "unknown") if isinstance(parsed_log, dict) else "unknown"
    total_lines = parsed_log.get("total_lines", 0) if isinstance(parsed_log, dict) else 0
    
    suspicious_list = parsed_log.get("suspicious_lines", []) if isinstance(parsed_log, dict) else []
    if isinstance(suspicious_list, list) and suspicious_list:
        suspicious_lines_str = "\n".join(suspicious_list[:25])
    else:
        suspicious_lines_str = "None detected."

    sample_str = raw_sample[:3000] if raw_sample else "(No sample provided)"

    prompt = _USER_PROMPT_TEMPLATE.format(
        log_type=log_type,
        total_lines=total_lines,
        raw_sample=sample_str,
        suspicious_lines=suspicious_lines_str
    )

    # 4. Call Groq API
    try:
        print("Attempting AI analysis...")
        client = Groq(api_key=api_key, http_client=None)
        chat_completion = client.chat.completions.create(
            model=_MODEL,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=_TEMPERATURE,
            max_tokens=_MAX_TOKENS,
        )
        print("AI analysis complete")
        return chat_completion.choices[0].message.content

    except RateLimitError as e:
        print(f"AI analysis failed: {e}")
        return (
            "[AI Analysis Unavailable]\n\n"
            "Groq API rate limit exceeded. Please wait a moment and try again."
        )
    except APIConnectionError as exc:
        print(f"AI analysis failed: {exc}")
        return (
            f"[AI Analysis Unavailable]\n\n"
            f"Could not connect to Groq API: {exc}\n"
            "Please verify your internet connection."
        )
    except APIError as exc:
        print(f"AI analysis failed: {exc}")
        return (
            f"[AI Analysis Unavailable]\n\n"
            f"Groq API returned an error: {exc.message} (status {exc.status_code})"
        )
    except Exception as exc:
        print(f"AI analysis failed: {exc}")
        return (
            f"[AI Analysis Unavailable]\n\n"
            f"An unexpected error occurred during AI log analysis: {exc}"
        )
