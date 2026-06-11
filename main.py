"""FastAPI backend for Ticket Scam Hunter — Vertex AI Agent Builder integration."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastmcp.utilities.lifespan import combine_lifespans
from pydantic import ValidationError

from mcp_server import mcp_app
from schemas import (
    ErrorResponse,
    ScanPipelineError,
    ScanResultResponse,
    ScanUrlRequest,
    SearchScansRequest,
    SearchScansResponse,
    Verdict,
)
from scanner import scan_ticket_url
from store import get_by_url, search_scams

logger = logging.getLogger(__name__)

API_VERSION = "1.0.0"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(level=logging.INFO)
    logger.info("Ticket Scam Hunter API starting (v%s)", API_VERSION)
    yield
    logger.info("Ticket Scam Hunter API shutting down")


app = FastAPI(
    title="Ticket Scam Hunter API",
    description=(
        "FIFA World Cup 2026 ticket scam detection service for "
        "Google Cloud Vertex AI Agent Builder and Elastic partner track."
    ),
    version=API_VERSION,
    lifespan=combine_lifespans(lifespan, mcp_app.lifespan),
    responses={
        422: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
        504: {"model": ErrorResponse},
    },
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.mount("/mcp", mcp_app)


@app.get("/health", tags=["system"])
async def health() -> dict:
    return {"status": "ok", "service": "ticket-scam-hunter", "version": API_VERSION}


def _pipeline_http_exception(exc: ScanPipelineError) -> HTTPException:
    return HTTPException(
        status_code=exc.status_code,
        detail=str(exc),
        headers={"X-Error-Code": exc.error_code},
    )


@app.post(
    "/v1/scans",
    response_model=ScanResultResponse,
    tags=["scans"],
    operation_id="scanTicketUrl",
    summary="Analyze a ticket URL for scam signals",
    responses={
        502: {"model": ErrorResponse, "description": "URL fetch or analysis failed"},
        504: {"model": ErrorResponse, "description": "Scan timed out"},
        500: {"model": ErrorResponse, "description": "Unexpected pipeline error"},
    },
)
async def create_scan(body: ScanUrlRequest) -> ScanResultResponse:
    url = str(body.url)
    try:
        return await asyncio.wait_for(scan_ticket_url(body), timeout=120.0)
    except asyncio.TimeoutError as exc:
        logger.error("Scan timed out for %s", url)
        raise HTTPException(
            status_code=504,
            detail="Scan timed out while fetching or analyzing the URL.",
            headers={"X-Error-Code": "scan_timeout"},
        ) from exc
    except ScanPipelineError as exc:
        logger.error(
            "Scan pipeline failed for %s [%s]: %s",
            url,
            exc.error_code,
            exc,
        )
        raise _pipeline_http_exception(exc) from exc
    except Exception as exc:
        logger.exception("Unexpected error during scan for %s", url)
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred during the scan.",
            headers={"X-Error-Code": "internal_error"},
        ) from exc


@app.get(
    "/v1/scans",
    response_model=SearchScansResponse,
    tags=["scans"],
    operation_id="searchScans",
    summary="Search stored scam scan results",
)
async def list_scans(
    verdict: Verdict | None = Query(default=None),
    query: str | None = Query(default=None, max_length=500),
) -> SearchScansResponse:
    try:
        params = SearchScansRequest(verdict=verdict, query=query)
        docs = await asyncio.to_thread(
            search_scams,
            verdict=params.verdict.value if params.verdict else None,
            query=params.query,
        )
        results = [
            ScanResultResponse(
                url=doc["url"],
                verdict=Verdict(doc["verdict"]),
                score=float(doc["score"]),
                reasons=doc.get("reasons", []),
                red_flags=doc.get("red_flags", []),
                trust_signals=doc.get("trust_signals", []),
                analyzed_at=doc.get("analyzed_at"),
                cached=True,
            )
            for doc in docs
        ]
        return SearchScansResponse(total=len(results), results=results)
    except EnvironmentError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get(
    "/v1/scans/cached",
    response_model=ScanResultResponse,
    tags=["scans"],
    operation_id="getCachedScan",
    summary="Return a previously stored scan for a URL",
)
async def cached_scan(
    url: str = Query(..., min_length=8, max_length=2048, description="Exact URL to look up."),
) -> ScanResultResponse:
    try:
        request = ScanUrlRequest(url=url, persist=False, force_refresh=False)
        doc = await asyncio.to_thread(get_by_url, str(request.url))
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except EnvironmentError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    if not doc:
        raise HTTPException(status_code=404, detail="No cached scan found for this URL.")

    return ScanResultResponse(
        url=doc["url"],
        verdict=Verdict(doc["verdict"]),
        score=float(doc["score"]),
        reasons=doc.get("reasons", []),
        red_flags=doc.get("red_flags", []),
        trust_signals=doc.get("trust_signals", []),
        analyzed_at=doc.get("analyzed_at"),
        cached=True,
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(_request: Request, exc: HTTPException):
    error_code = None
    if exc.headers:
        error_code = exc.headers.get("X-Error-Code")
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            detail=str(exc.detail),
            error_code=error_code or f"http_{exc.status_code}",
        ).model_dump(),
        headers={k: v for k, v in (exc.headers or {}).items() if k != "X-Error-Code"},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception(
        "Unhandled error on %s %s",
        request.method,
        request.url.path,
    )
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            detail="Internal server error",
            error_code="internal_error",
        ).model_dump(),
    )
