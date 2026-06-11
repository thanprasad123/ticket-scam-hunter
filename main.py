"""FastAPI backend for Ticket Scam Hunter — Vertex AI Agent Builder integration."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from requests.exceptions import RequestException

from schemas import (
    ErrorResponse,
    ScanResultResponse,
    ScanUrlRequest,
    ScanPipelineError,
    SearchScansRequest,
    SearchScansResponse,
    Verdict,
)
from scanner import scan_ticket_url
from mcp_server import mcp_app
from store import get_by_url, search_scams

logger = logging.getLogger(__name__)
API_VERSION = "1.0.0"
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"


def _doc_to_scan_response(doc: dict) -> ScanResultResponse:
    return ScanResultResponse(
        url=doc["url"],
        verdict=Verdict(doc["verdict"]),
        score=float(doc["score"]),
        reasons=doc.get("reasons", []),
        red_flags=doc.get("red_flags", []),
        trust_signals=doc.get("trust_signals", []),
        analyzed_at=doc.get("analyzed_at") or datetime.now(timezone.utc),
        cached=True,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(level=logging.INFO)
    logger.info("Ticket Scam Hunter API starting (v%s)", API_VERSION)
    async with mcp_app.lifespan(app):
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
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Serve static UI
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

for route in mcp_app.routes:
    app.router.routes.append(route)

@app.get("/", include_in_schema=False)
async def serve_ui():
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return {"message": "Ticket Scam Hunter API", "docs": "/docs"}


@app.get("/health", tags=["system"])
async def health() -> dict:
    return {"status": "ok", "service": "ticket-scam-hunter", "version": API_VERSION}




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
    except ScanPipelineError:
        raise
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
            raise_errors=True,
        )
        results = []
        for doc in docs:
            try:
                results.append(_doc_to_scan_response(doc))
            except (ValidationError, ValueError, KeyError) as exc:
                logger.warning("Skipping invalid Elasticsearch scan document: %s", exc)
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
        doc = await asyncio.to_thread(get_by_url, str(request.url), raise_errors=True)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except EnvironmentError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    if not doc:
        raise HTTPException(status_code=404, detail="No cached scan found for this URL.")

    try:
        return _doc_to_scan_response(doc)
    except (ValidationError, ValueError, KeyError) as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Invalid cached scan document: {exc}",
        ) from exc


@app.exception_handler(ScanPipelineError)
async def scan_pipeline_exception_handler(_request: Request, exc: ScanPipelineError):
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            detail=str(exc),
            error_code=exc.error_code,
        ).model_dump(),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content=ErrorResponse(
            detail=str(exc),
            error_code="validation_error",
        ).model_dump(),
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
