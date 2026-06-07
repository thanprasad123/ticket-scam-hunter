"""Async orchestration for URL scanning with retries and Elasticsearch cache."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import requests
from requests.exceptions import RequestException

from analyze import analyze_with_gemini, fetch_page_text, format_result
from schemas import (
    URGENCY_PATTERNS,
    PageMeta,
    ScanResultResponse,
    ScanUrlRequest,
    Verdict,
)
from store import get_by_url, store_result

FETCH_TIMEOUT_SEC = 20
FETCH_MAX_ATTEMPTS = 3
FETCH_BACKOFF_SEC = 1.0


def _detect_urgency_flags(texts: list[str]) -> list[str]:
    combined = " ".join(texts).lower()
    flags = []
    for pattern in URGENCY_PATTERNS:
        if pattern in combined:
            flags.append(f"High-urgency payment pattern detected: {pattern}")
    return flags


def _fetch_page_with_retry(url: str) -> tuple[str, dict]:
    last_error: RequestException | None = None
    for attempt in range(FETCH_MAX_ATTEMPTS):
        try:
            return fetch_page_text(url, timeout=FETCH_TIMEOUT_SEC)
        except RequestException as exc:
            last_error = exc
            if attempt < FETCH_MAX_ATTEMPTS - 1:
                import time

                time.sleep(FETCH_BACKOFF_SEC * (2**attempt))
    assert last_error is not None
    raise last_error


def _es_doc_to_response(doc: dict, cached: bool = True) -> ScanResultResponse:
    return ScanResultResponse(
        url=doc["url"],
        verdict=Verdict(doc["verdict"]),
        score=float(doc["score"]),
        reasons=doc.get("reasons", []),
        red_flags=doc.get("red_flags", []),
        trust_signals=doc.get("trust_signals", []),
        analyzed_at=doc.get("analyzed_at") or datetime.now(timezone.utc),
        cached=cached,
    )


async def scan_ticket_url(request: ScanUrlRequest) -> ScanResultResponse:
    url = str(request.url)

    if not request.force_refresh:
        cached_doc = await asyncio.to_thread(get_by_url, url)
        if cached_doc:
            return _es_doc_to_response(cached_doc, cached=True)

    page_text, meta = await asyncio.to_thread(_fetch_page_with_retry, url)
    analysis = await asyncio.to_thread(analyze_with_gemini, url, page_text, meta)
    result = format_result(url, analysis, meta)

    red_flags = list(result.get("red_flags", []))
    red_flags.extend(
        _detect_urgency_flags(
            result["reasons"] + red_flags + result.get("trust_signals", [])
        )
    )

    response = ScanResultResponse(
        url=result["url"],
        verdict=Verdict(result["verdict"]),
        score=float(result["score"]),
        reasons=result["reasons"],
        red_flags=red_flags,
        trust_signals=result.get("trust_signals", []),
        analyzed_at=result["analyzed_at"],
        page=PageMeta(**meta) if meta else None,
        cached=False,
    )

    if request.persist:
        doc_id = await asyncio.to_thread(store_result, result)
        response.document_id = doc_id

    return response
