"""Async orchestration for URL scanning with retries and Elasticsearch cache."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone

from pydantic import ValidationError
from requests.exceptions import RequestException

from analyze import analyze_with_gemini, fetch_page_text, format_result
from schemas import (
    URGENCY_PATTERNS,
    AnalysisError,
    PageMeta,
    ScanResponseError,
    ScanResultResponse,
    ScanUrlRequest,
    UrlFetchError,
    Verdict,
)
from store import get_by_url, store_result

logger = logging.getLogger(__name__)

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
            logger.warning(
                "Fetch attempt %d/%d failed for %s: %s",
                attempt + 1,
                FETCH_MAX_ATTEMPTS,
                url,
                exc,
            )
            if attempt < FETCH_MAX_ATTEMPTS - 1:
                time.sleep(FETCH_BACKOFF_SEC * (2**attempt))

    detail = str(last_error) if last_error is not None else "unknown network error"
    raise UrlFetchError(
        f"Failed to fetch URL after {FETCH_MAX_ATTEMPTS} attempts: {detail}",
        cause=last_error,
    )


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
            try:
                return _es_doc_to_response(cached_doc, cached=True)
            except (ValidationError, ValueError, KeyError) as exc:
                logger.warning(
                    "Invalid cached document for %s, running fresh scan: %s",
                    url,
                    exc,
                )

    try:
        page_text, meta = await asyncio.to_thread(_fetch_page_with_retry, url)
    except UrlFetchError:
        raise
    except RequestException as exc:
        logger.error("Unexpected fetch error for %s: %s", url, exc)
        raise UrlFetchError(f"Failed to fetch URL: {exc}", cause=exc) from exc

    try:
        analysis = await asyncio.to_thread(analyze_with_gemini, url, page_text, meta)
        result = format_result(url, analysis, meta)
    except (json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
        logger.error("Invalid Gemini response for %s: %s", url, exc)
        raise AnalysisError(f"Invalid analysis response: {exc}", cause=exc) from exc
    except Exception as exc:
        logger.error("Gemini analysis failed for %s: %s", url, exc)
        raise AnalysisError(f"Gemini analysis failed: {exc}", cause=exc) from exc

    red_flags = list(result.get("red_flags", []))
    red_flags.extend(
        _detect_urgency_flags(
            result["reasons"] + red_flags + result.get("trust_signals", [])
        )
    )

    try:
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
    except (ValidationError, ValueError, KeyError) as exc:
        logger.error("Scan result validation failed for %s: %s", url, exc)
        raise ScanResponseError(f"Invalid scan result: {exc}", cause=exc) from exc

    if request.persist:
        doc_id = await asyncio.to_thread(store_result, result)
        if doc_id is None:
            logger.warning(
                "Scan succeeded but Elasticsearch persist failed for %s",
                url,
            )
        else:
            response.document_id = doc_id

    return response
