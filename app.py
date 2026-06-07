"""Ticket Scam Hunter — Streamlit demo UI."""

from __future__ import annotations

import asyncio
import os
from datetime import datetime

import streamlit as st
from elasticsearch import Elasticsearch
from pydantic import ValidationError

from analyze import analyze_with_gemini, format_result
from async_utils import run_async
from schemas import (
    PageMeta,
    ScanResultResponse,
    ScanUrlRequest,
    SearchScansRequest,
    Verdict,
)
from scanner import _detect_urgency_flags, _fetch_page_with_retry, get_by_url
from store import get_es_client, search_scams, store_result

# ---------------------------------------------------------------------------
# Backend integration (wrappers for scanner + Elasticsearch)
# ---------------------------------------------------------------------------


def _normalize_payload_keys(payload: dict) -> dict:
    """Map capitalized or spaced keys (e.g. Verdict) to lowercase schema names."""
    return {str(key).lower().replace(" ", "_"): value for key, value in payload.items()}


def _prepare_analysis_payload(data: dict) -> dict:
    """Normalize Gemini output and apply the same fallbacks as analyze.py."""
    data = _normalize_payload_keys(data)
    if "verdict" in data and isinstance(data["verdict"], str):
        data["verdict"] = data["verdict"].upper()
    if "score" not in data:
        defaults = {"SCAM": 8, "SUSPICIOUS": 5, "LEGITIMATE": 1}
        data["score"] = defaults.get(str(data.get("verdict", "SUSPICIOUS")).upper(), 5)
    if "reasons" not in data or not data["reasons"]:
        reason = data.get("reason") or data.get("reasons", "See verdict")
        if isinstance(reason, str):
            data["reasons"] = [reason]
    data.setdefault("red_flags", [])
    data.setdefault("trust_signals", [])
    return data


async def _collect_scan_payload(request: ScanUrlRequest) -> dict:
    """Run the scan pipeline with normalized Gemini keys before validation."""
    url = str(request.url)

    if not request.force_refresh:
        cached_doc = await asyncio.to_thread(get_by_url, url)
        if cached_doc:
            normalized = _normalize_payload_keys(dict(cached_doc))
            return ScanResultResponse.model_validate(
                {**normalized, "cached": True}
            ).model_dump(mode="json")

    page_text, meta = await asyncio.to_thread(_fetch_page_with_retry, url)
    analysis = await asyncio.to_thread(analyze_with_gemini, url, page_text, meta)
    analysis = _prepare_analysis_payload(analysis)
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
    return _normalize_payload_keys(response.model_dump(mode="json"))


def _storage_payload(scan_dict: dict) -> dict:
    return {
        "url": scan_dict["url"],
        "verdict": scan_dict["verdict"],
        "score": scan_dict["score"],
        "reasons": scan_dict.get("reasons", []),
        "red_flags": scan_dict.get("red_flags", []),
        "trust_signals": scan_dict.get("trust_signals", []),
        "analyzed_at": scan_dict.get("analyzed_at"),
    }


def run_scam_analysis(url: str, force_refresh: bool = False) -> dict:
    """Run Gemini analysis without persisting. Returns a JSON-serializable dict."""
    request = ScanUrlRequest(url=url, persist=False, force_refresh=force_refresh)
    return run_async(_collect_scan_payload(request))


def save_to_elasticsearch(url: str, raw_payload: dict) -> str:
    """Persist a scan result to the scam-sites index. Returns document ID."""
    payload = dict(raw_payload)
    payload["url"] = url
    return store_result(payload)


@st.cache_resource
def get_cached_es_client() -> Elasticsearch:
    """Initialize Elasticsearch once per session using ES_API_KEY."""
    return get_es_client()


# ---------------------------------------------------------------------------
# UI theme
# ---------------------------------------------------------------------------

VERDICT_STYLES: dict[Verdict, dict[str, str]] = {
    Verdict.SCAM: {
        "bg": "linear-gradient(135deg, #2a0a0a 0%, #4a1010 100%)",
        "border": "#f87171",
        "text": "#fecaca",
        "accent": "#ef4444",
        "glow": "rgba(239, 68, 68, 0.25)",
        "label": "🚨 SCAM",
    },
    Verdict.SUSPICIOUS: {
        "bg": "linear-gradient(135deg, #2a1f08 0%, #4a3510 100%)",
        "border": "#fbbf24",
        "text": "#fde68a",
        "accent": "#f59e0b",
        "glow": "rgba(245, 158, 11, 0.22)",
        "label": "⚠️ SUSPICIOUS",
    },
    Verdict.LEGITIMATE: {
        "bg": "linear-gradient(135deg, #0a2216 0%, #104a28 100%)",
        "border": "#4ade80",
        "text": "#bbf7d0",
        "accent": "#22c55e",
        "glow": "rgba(34, 197, 94, 0.22)",
        "label": "✅ LEGITIMATE",
    },
}


def inject_custom_css() -> None:
    st.markdown(
        """
        <style>
        /* Layout polish — backgrounds defer to .streamlit/config.toml theme */
        .block-container {
            padding-top: 1.25rem;
            padding-bottom: 2rem;
            max-width: 1140px;
        }

        h1 {
            letter-spacing: -0.02em;
            font-weight: 700 !important;
            margin-bottom: 0.35rem !important;
        }

        .tech-badge-row {
            display: flex;
            flex-wrap: wrap;
            gap: 0.65rem;
            margin: 0.5rem 0 1.35rem 0;
        }

        .tech-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
            padding: 0.45rem 0.85rem;
            border-radius: 999px;
            font-size: 0.82rem;
            font-weight: 600;
            letter-spacing: 0.01em;
            border: 1px solid #2a3142;
            color: #e2e8f0;
            white-space: nowrap;
        }

        .tech-badge.target { border-color: #3b82f6; color: #bfdbfe; }
        .tech-badge.engine { border-color: #8b5cf6; color: #ddd6fe; }
        .tech-badge.storage { border-color: #10b981; color: #a7f3d0; }

        .verdict-banner {
            border-radius: 14px;
            padding: 1.35rem 1.6rem;
            margin: 0.25rem 0 1.1rem 0;
            border: 1px solid var(--border);
            background: var(--bg);
            color: var(--text);
            box-shadow: 0 8px 28px var(--glow);
        }

        .verdict-banner h2 {
            margin: 0;
            font-size: 1.65rem;
            font-weight: 700;
            color: var(--text);
            letter-spacing: -0.01em;
        }

        .verdict-banner p {
            margin: 0.4rem 0 0;
            font-size: 1rem;
            opacity: 0.92;
        }

        .section-card {
            border: 1px solid #2a3142;
            border-radius: 12px;
            padding: 1rem 1.2rem;
            margin-bottom: 0.65rem;
        }

        .section-card h4 {
            margin-top: 0;
            margin-bottom: 0.55rem;
            font-size: 0.95rem;
        }

        /* live_scan_form — high-contrast text (theme-safe, no background overrides) */
        div[data-testid="stForm"] {
            border: 1px solid #2a3142;
            border-radius: 14px;
            padding: 1.1rem 1.25rem 0.85rem;
        }

        div[data-testid="stWidgetLabel"] label p,
        div[data-testid="stForm"] div[data-testid="stWidgetLabel"] label p {
            color: #ffffff !important;
            font-weight: 600 !important;
        }

        div[data-testid="stCheckbox"] label p,
        div[data-testid="stForm"] div[data-testid="stCheckbox"] label p {
            color: #e2e8f0 !important;
        }

        div[data-testid="stForm"] div[data-testid="stTextInput"] input,
        div[data-testid="stForm"] div[data-testid="stTextInput"] textarea {
            color: #ffffff !important;
        }

        div[data-testid="stForm"] div[data-testid="stTextInput"] input::placeholder,
        div[data-testid="stForm"] div[data-testid="stTextInput"] textarea::placeholder {
            color: #94a3b8 !important;
            opacity: 1 !important;
        }

        div[data-testid="stForm"] .stCaption,
        div[data-testid="stForm"] small,
        div[data-testid="stForm"] div[data-testid="stCaptionContainer"],
        div[data-testid="stForm"] div[data-testid="stCaptionContainer"] p {
            color: #94a3b8 !important;
        }

        div[data-testid="stMetric"] {
            border: 1px solid #2a3142;
            border-radius: 10px;
            padding: 0.65rem 0.85rem;
        }

        div[data-testid="stMetricValue"] {
            font-size: 1.45rem;
            font-weight: 700;
        }

        div[data-testid="stMetricLabel"] {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }

        div[data-testid="stProgress"] > div > div {
            border-radius: 6px;
        }

        div[data-testid="stTabs"] {
            margin-top: 0.25rem;
        }

        section[data-testid="stSidebar"] .block-container {
            padding-top: 1rem;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_tech_badges() -> None:
    badge_col1, badge_col2, badge_col3 = st.columns(3)
    with badge_col1:
        st.markdown(
            '<div class="tech-badge target">🎯 Target: FIFA World Cup 2026</div>',
            unsafe_allow_html=True,
        )
    with badge_col2:
        st.markdown(
            '<div class="tech-badge engine">⚡ Engine: Gemini 2.5 Flash via Vertex AI</div>',
            unsafe_allow_html=True,
        )
    with badge_col3:
        st.markdown(
            '<div class="tech-badge storage">💾 Index: Elasticsearch Cloud</div>',
            unsafe_allow_html=True,
        )


def render_sidebar_infrastructure_status() -> None:
    es_ok = bool(os.environ.get("ES_API_KEY"))
    st.divider()
    st.markdown("**Infrastructure**")
    if es_ok:
        st.sidebar.success("● Elasticsearch Online")
    else:
        st.sidebar.error("○ Elasticsearch Offline")


def verdict_banner(result: ScanResultResponse) -> None:
    style = VERDICT_STYLES[result.verdict]
    cached_note = " · served from cache" if result.cached else ""
    st.markdown(
        f"""
        <div class="verdict-banner" style="
            --bg:{style['bg']};
            --border:{style['border']};
            --text:{style['text']};
            --glow:{style['glow']};
        ">
            <h2>{style['label']}</h2>
            <p>Risk score <strong>{result.score:.1f}</strong> / 10{cached_note}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_bullet_section(title: str, items: list[str], icon: str, empty_msg: str) -> None:
    st.markdown('<div class="section-card">', unsafe_allow_html=True)
    st.markdown(f"#### {icon} {title}")
    if items:
        for item in items:
            st.markdown(f"- {item}")
    else:
        st.caption(empty_msg)
    st.markdown("</div>", unsafe_allow_html=True)


def render_scan_result(result: ScanResultResponse) -> None:
    verdict_banner(result)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Risk score", f"{result.score:.1f} / 10")
    col2.metric("Verdict", result.verdict.value)
    col3.metric("Cached", "Yes" if result.cached else "No")
    col4.metric(
        "Analyzed",
        result.analyzed_at.strftime("%Y-%m-%d %H:%M UTC")
        if isinstance(result.analyzed_at, datetime)
        else str(result.analyzed_at)[:16],
    )

    st.progress(min(result.score / 10.0, 1.0))

    if result.page:
        with st.expander("Page metadata", expanded=False):
            st.json(result.page.model_dump())

    left, right = st.columns(2)
    with left:
        render_bullet_section(
            "Red flags",
            result.red_flags,
            "🚩",
            "No red flags detected.",
        )
    with right:
        render_bullet_section(
            "Trust signals",
            result.trust_signals,
            "🛡️",
            "No trust signals recorded.",
        )

    render_bullet_section(
        "Reasons",
        result.reasons,
        "📋",
        "No reasons returned.",
    )

    if result.document_id:
        st.success(f"Saved to Elasticsearch · document `{result.document_id}`")


def execute_live_scan(url: str, persist: bool, force_refresh: bool) -> ScanResultResponse | None:
    try:
        request = ScanUrlRequest(
            url=url,
            persist=persist,
            force_refresh=force_refresh,
        )
    except ValidationError as exc:
        st.error(format_validation_error(exc))
        return None

    with st.spinner("Fetching page and running Gemini analysis…"):
        try:
            raw = run_async(_collect_scan_payload(request))
            if persist:
                doc_id = run_async(asyncio.to_thread(store_result, _storage_payload(raw)))
                raw["document_id"] = doc_id
            result = ScanResultResponse.model_validate(_normalize_payload_keys(raw))
        except ValidationError as exc:
            st.error(format_validation_error(exc))
            return None
        except KeyError as exc:
            missing = exc.args[0] if exc.args else "unknown"
            st.error(
                "The AI model returned an incomplete scan payload. "
                f"Missing required field: '{missing}'. "
                "Try again or enable **Force Fresh Scan (Bypass Cache)**."
            )
            return None
        except EnvironmentError as exc:
            st.error(f"Configuration error: {exc}")
            return None
        except Exception as exc:
            st.error(f"Scan failed: {exc}")
            return None

    return result


def format_validation_error(exc: ValidationError) -> str:
    lines = ["Input validation failed:"]
    for err in exc.errors():
        loc = " → ".join(str(part) for part in err.get("loc", ()))
        lines.append(f"- **{loc}**: {err.get('msg', 'invalid')}")
    return "\n".join(lines)


def render_live_scan_tab() -> None:
    st.subheader("Analyze a ticket URL")
    st.caption(
        "Submit a FIFA World Cup 2026 ticket sales URL. "
        "Results are validated against `ScanResultResponse` before display."
    )

    with st.form("live_scan_form", clear_on_submit=False):
        url_input = st.text_input(
            "Ticket URL",
            placeholder="https://example.com/tickets",
            help="Must be a valid HTTP/HTTPS URL (max 2048 characters).",
        )

        opt_col1, opt_col2 = st.columns(2, gap="medium")
        with opt_col1:
            persist = st.checkbox(
                "💾 Save Scan Results to Elasticsearch",
                value=True,
                help="Maps to `ScanUrlRequest.persist`.",
            )
        with opt_col2:
            force_refresh = st.checkbox(
                "⚡ Force Fresh Scan (Bypass Cache)",
                value=False,
                help="Maps to `ScanUrlRequest.force_refresh` — skips cache.",
            )

        submitted = st.form_submit_button(
            "Run scan",
            type="primary",
            use_container_width=True,
        )

    if submitted:
        if not url_input.strip():
            st.error("Please enter a URL to scan.")
            return
        result = execute_live_scan(url_input.strip(), persist, force_refresh)
        if result:
            st.divider()
            render_scan_result(result)


def render_history_tab() -> None:
    st.subheader("Search scan history")
    st.caption("Query the `scam-sites` Elasticsearch index.")

    if not os.environ.get("ES_API_KEY"):
        st.warning("Set `ES_API_KEY` in your environment to load scan history.")
        return

    col_search, col_verdict = st.columns([2, 1])
    with col_search:
        keyword = st.text_input(
            "Keyword search",
            placeholder="Search URL, reasons, or red flags…",
            label_visibility="collapsed",
        )
    with col_verdict:
        verdict_options = ["All verdicts"] + [v.value for v in Verdict]
        verdict_choice = st.selectbox(
            "Verdict filter",
            options=verdict_options,
            label_visibility="collapsed",
        )

    if st.button("Search history", type="primary", use_container_width=True):
        try:
            verdict_filter = None
            if verdict_choice != "All verdicts":
                verdict_filter = Verdict(verdict_choice)

            params = SearchScansRequest(
                verdict=verdict_filter,
                query=keyword or None,
            )
        except ValidationError as exc:
            st.error(format_validation_error(exc))
            return

        with st.spinner("Searching Elasticsearch…"):
            try:
                es = get_cached_es_client()
                docs = search_scams(
                    verdict=params.verdict.value if params.verdict else None,
                    query=params.query,
                    es=es,
                )
            except EnvironmentError as exc:
                st.error(f"Elasticsearch error: {exc}")
                return
            except Exception as exc:
                st.error(f"Search failed: {exc}")
                return

        if not docs:
            st.info("No matching scans found.")
            return

        st.success(f"Found {len(docs)} result(s)")
        for doc in docs:
            try:
                result = ScanResultResponse.model_validate(
                    {
                        **doc,
                        "cached": True,
                    }
                )
            except ValidationError as exc:
                st.error(f"Invalid stored record for {doc.get('url')}: {exc}")
                continue

            style = VERDICT_STYLES[result.verdict]
            with st.expander(
                f"{style['label']} · {result.score:.1f}/10 · {result.url}",
                expanded=False,
            ):
                st.markdown(
                    f"**Verdict:** `{result.verdict.value}` · "
                    f"**Score:** `{result.score:.1f}` · "
                    f"**Analyzed:** `{result.analyzed_at}`"
                )
                if result.reasons:
                    st.markdown("**Reasons**")
                    for reason in result.reasons:
                        st.markdown(f"- {reason}")
                if result.red_flags:
                    st.markdown("**Red flags**")
                    for flag in result.red_flags:
                        st.markdown(f"- {flag}")
                if result.trust_signals:
                    st.markdown("**Trust signals**")
                    for signal in result.trust_signals:
                        st.markdown(f"- {signal}")


def main() -> None:
    st.set_page_config(
        page_title="Ticket Scam Hunter",
        page_icon="🎟️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    inject_custom_css()

    st.title("🎟️ Ticket Scam Hunter")
    render_tech_badges()

    with st.sidebar:
        st.header("About")
        st.markdown(
            """
            **Live Scan** validates URLs with `ScanUrlRequest`, runs the
            Gemini analyzer, and renders a `ScanResultResponse`.

            **Scan History** searches prior results in Elastic Cloud.
            """
        )
        render_sidebar_infrastructure_status()

    tab_scan, tab_history = st.tabs(["🔍 Live Scan", "📊 Scan History"])
    with tab_scan:
        render_live_scan_tab()
    with tab_history:
        render_history_tab()


if __name__ == "__main__":
    main()
