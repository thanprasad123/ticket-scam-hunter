#!/usr/bin/env python3
"""Day 1: Analyze a ticket-sales URL for FIFA World Cup 2026 scam signals via Gemini."""

import argparse
import json
import re
import sys
from datetime import datetime, timezone

from google import genai
import requests
from bs4 import BeautifulSoup

MODEL = "gemini-2.5-flash"
MAX_PAGE_CHARS = 12_000
USER_AGENT = (
    "Mozilla/5.0 (compatible; TicketScamHunter/1.0; +https://github.com/hackathon)"
)

ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "score": {
            "type": "number",
            "description": "Scam likelihood from 0 (legitimate) to 10 (definite scam).",
        },
        "verdict": {
            "type": "string",
            "enum": ["SCAM", "LEGITIMATE", "SUSPICIOUS"],
        },
        "reasons": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Short bullet reasons supporting the verdict.",
        },
        "red_flags": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Specific scam indicators found on the page, if any.",
        },
        "trust_signals": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Legitimacy indicators, if any.",
        },
    },
    "required": ["score", "verdict", "reasons"],
}

SYSTEM_PROMPT = """You are Ticket Scam Hunter, an expert analyst for FIFA World Cup 2026 ticket fraud.

Analyze the provided webpage text and metadata for signs of fraudulent ticket resale or phishing.

Official FIFA ticketing uses FIFA.com and authorized partners only. Common scam patterns:
- Domains mimicking FIFA, FIFA+, or official partners
- Prices far below market or "limited time" pressure
- Wire transfer, crypto, gift cards, or unofficial payment apps
- No verifiable company identity, address, or customer support
- Grammar/spelling issues and generic stock imagery
- Claims of "guaranteed" seats without official resale program
- Requests for passwords, bank logins, or excessive personal data

Be calibrated: SUSPICIOUS for mixed signals, SCAM only when evidence is strong, LEGITIMATE only when the site clearly matches known official channels.

Base your judgment only on the supplied content (you cannot browse live). If content is thin or blocked, lean SUSPICIOUS and say why."""


def fetch_page_text(url: str, timeout: int = 20) -> tuple[str, dict]:
    """Fetch URL and return plain text plus metadata for analysis."""
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"}
    resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    title = (soup.title.string or "").strip() if soup.title else ""
    text = soup.get_text(separator="\n", strip=True)
    text = re.sub(r"\n{3,}", "\n\n", text)
    if len(text) > MAX_PAGE_CHARS:
        text = text[:MAX_PAGE_CHARS] + "\n\n[... truncated ...]"

    meta = {
        "final_url": resp.url,
        "status_code": resp.status_code,
        "title": title,
        "content_length": len(resp.text),
        "text_length": len(text),
    }
    return text, meta


def analyze_with_gemini(url: str, page_text: str, meta: dict) -> dict:
    client = genai.Client(
        vertexai=True,
        project="gen-lang-client-0799569470",
        location="us-central1",
    )

    user_content = f"""URL submitted: {url}
Final URL after redirects: {meta.get("final_url", url)}
HTTP status: {meta.get("status_code")}
Page title: {meta.get("title") or "(none)"}

--- PAGE TEXT ---
{page_text or "(no extractable text)"}
"""

    response = client.models.generate_content(
        model=MODEL,
        contents=user_content,
        config=genai.types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            temperature=0.2,
            response_mime_type="application/json",
        ),
    )

    raw = response.text.strip()
    data = json.loads(raw)

    # Normalize field names
    if "verdict" not in data:
        # Try to find verdict under different keys
        data["verdict"] = data.get("verdict", "SUSPICIOUS")

    if "reasons" not in data or not data["reasons"]:
        reason = data.get("reason") or data.get("reasoning") or "See verdict"
        if isinstance(reason, str):
            data["reasons"] = [reason]
        else:
            data["reasons"] = reason if reason else ["Analysis inconclusive"]

    if "score" not in data:
        defaults = {"SCAM": 8, "SUSPICIOUS": 5, "LEGITIMATE": 1}
        data["score"] = defaults.get(data.get("verdict", "SUSPICIOUS"), 5)
    data.setdefault("red_flags", [])
    data.setdefault("trust_signals", [])
    return data


def format_result(url: str, analysis: dict, meta: dict) -> dict:
    return {
        "url": url,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "page": meta,
        "score": analysis["score"],
        "verdict": analysis["verdict"],
        "reasons": analysis.get("reasons", []),
        "red_flags": analysis.get("red_flags", []),
        "trust_signals": analysis.get("trust_signals", []),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze a URL for FIFA World Cup 2026 ticket scam signals."
    )
    parser.add_argument("url", help="Ticket sales page URL to analyze")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print full result as JSON (default: human-readable summary)",
    )
    args = parser.parse_args()

    try:
        page_text, meta = fetch_page_text(args.url)
        analysis = analyze_with_gemini(args.url, page_text, meta)
        result = format_result(args.url, analysis, meta)
    except requests.RequestException as e:
        print(f"Failed to fetch URL: {e}", file=sys.stderr)
        return 1
    except (json.JSONDecodeError, KeyError) as e:
        print(f"Analysis error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n{'=' * 60}")
        print(f"URL:     {result['url']}")
        if meta.get("final_url") and meta["final_url"] != args.url:
            print(f"Final:   {meta['final_url']}")
        print(f"Title:   {meta.get('title') or '(none)'}")
        print(f"{'=' * 60}")
        print(f"SCORE:   {result['score']}/10")
        print(f"VERDICT: {result['verdict']}")
        print(f"{'=' * 60}")
        print("\nReasons:")
        for r in result["reasons"]:
            print(f"  • {r}")
        if result.get("red_flags"):
            print("\nRed flags:")
            for f in result["red_flags"]:
                print(f"  ⚠ {f}")
        if result.get("trust_signals"):
            print("\nTrust signals:")
            for t in result["trust_signals"]:
                print(f"  ✓ {t}")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
