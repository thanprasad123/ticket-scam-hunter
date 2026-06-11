"""MCP tools for Ticket Scam Hunter."""

from __future__ import annotations

import asyncio

from fastmcp import FastMCP
from pydantic import ValidationError

from scanner import scan_ticket_url as run_scan
from schemas import (
    ScanPipelineError,
    ScanResultResponse,
    ScanUrlRequest,
    SearchScansRequest,
    Verdict,
)
from store import search_scams as search_stored_scams

mcp = FastMCP(
    "ticket-scam-hunter",
    instructions=(
        "Analyze FIFA World Cup 2026 ticket URLs for scam signals and search "
        "previously stored scan results."
    ),
)


def _scan_result_to_dict(result: ScanResultResponse) -> dict:
    return result.model_dump(mode="json", exclude_none=True)


def _stored_doc_to_scan_result(doc: dict) -> dict:
    return _scan_result_to_dict(
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
    )


def _tool_error_response(detail: str, error_code: str) -> dict:
    return {"error": {"detail": detail, "error_code": error_code}}


@mcp.tool(name="scan_ticket_url")
async def scan_ticket_url_tool(
    url: str,
    persist: bool = True,
    force_refresh: bool = False,
) -> dict:
    """Analyze a ticket website URL for FIFA World Cup 2026 scam signals."""
    request = ScanUrlRequest(
        url=url,
        persist=persist,
        force_refresh=force_refresh,
    )
    try:
        result = await asyncio.wait_for(run_scan(request), timeout=120.0)
        return _scan_result_to_dict(result)
    except ScanPipelineError as exc:
        return _tool_error_response(str(exc), exc.error_code)
    except ValidationError as exc:
        return _tool_error_response(str(exc), "validation_error")
    except Exception as exc:
        return _tool_error_response(
            f"Internal tool error scanning URL: {exc}",
            "internal_error",
        )


@mcp.tool(name="search_scams")
async def search_scams_tool(
    verdict: Verdict | None = None,
    query: str | None = None,
) -> dict:
    """Search previously detected scam sites in Elasticsearch."""
    params = SearchScansRequest(verdict=verdict, query=query)
    try:
        docs = await asyncio.to_thread(
            search_stored_scams,
            verdict=params.verdict.value if params.verdict else None,
            query=params.query,
        )
        results = []
        for doc in docs:
            try:
                results.append(_stored_doc_to_scan_result(doc))
            except (ValidationError, ValueError, KeyError):
                continue
        return {"total": len(results), "results": results}
    except EnvironmentError as exc:
        return _tool_error_response(str(exc), "elasticsearch_unavailable")
    except Exception as exc:
        return _tool_error_response(
            f"Internal tool error searching scams: {exc}",
            "internal_error",
        )


mcp_app = mcp.http_app(path="/mcp", stateless_http=True, json_response=True)

if __name__ == "__main__":
    mcp.run(
        transport="http",
        host="0.0.0.0",
        port=8001,
        path="/mcp",
        stateless_http=True,
        json_response=True,
    )
