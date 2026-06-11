"""FastAPI backend for Ticket Scam Hunter — Vertex AI Agent Builder integration."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from requests.exceptions import RequestException

from schemas import (
    ErrorResponse,
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
    description="FIFA World Cup 2026 ticket scam detection service.",
    version=API_VERSION,
    lifespan=lifespan,
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

# Serve static UI
import os
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", include_in_schema=False)
async def serve_ui():
    if os.path.exists("static/index.html"):
        return FileResponse("static/index.html")
    return {"message": "Ticket Scam Hunter API", "docs": "/docs"}


@app.get("/health", tags=["system"])
async def health() -> dict:
    return {"status": "ok", "service": "ticket-scam-hunter", "version": API_VERSION}


@app.api_route("/mcp", methods=["GET", "POST"], tags=["mcp"])
async def mcp_tools():
    return {
        "tools": [
            {
                "name": "scan_ticket_url",
                "description": "Analyze a ticket website URL for FIFA World Cup 2026 scam signals",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "The ticket website URL to analyze"}
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "search_scams",
                "description": "Search previously detected scam sites in Elasticsearch",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "verdict": {"type": "string", "enum": ["SCAM", "SUSPICIOUS", "LEGITIMATE"]}
                    }
                }
            }
        ]
    }


@app.post(
    "/v1/scans",
    response_model=ScanResultResponse,
    tags=["scans"],
    operation_id="scanTicketUrl",
    summary="Analyze a ticket URL for scam signals",
)
async def create_scan(body: ScanUrlRequest) -> ScanResultResponse:
    try:
        return await asyncio.wait_for(scan_ticket_url(body), timeout=120.0)
    except asyncio.TimeoutError as exc:
        raise HTTPException(status_code=504, detail="Scan timed out.") from exc
    except RequestException as exc:
        raise HTTPException(status_code=502, detail=f"Failed to fetch URL: {exc}") from exc
    except EnvironmentError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (ValidationError, ValueError, KeyError) as exc:
        raise HTTPException(status_code=500, detail=f"Invalid analysis response: {exc}") from exc


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
    url: str = Query(..., min_length=8, max_length=2048),
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
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            detail=str(exc.detail),
            error_code=f"http_{exc.status_code}",
        ).model_dump(),
    )