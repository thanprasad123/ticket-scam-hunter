"""Store and retrieve Ticket Scam Hunter scan results in Elasticsearch."""

import logging
import os
from datetime import datetime, timezone

from elasticsearch import Elasticsearch

logger = logging.getLogger(__name__)

DEFAULT_ES_ENDPOINT = (
    "https://697bbb480339473190e87012c2d7d8f4.us-central1.gcp.cloud.es.io:443"
)
DEFAULT_INDEX = "scam-sites"
DEFAULT_REQUEST_TIMEOUT = 5.0
DEFAULT_MAX_RETRIES = 0

INDEX_MAPPINGS = {
    "properties": {
        "url": {"type": "keyword"},
        "verdict": {"type": "keyword"},
        "score": {"type": "float"},
        "reasons": {"type": "text"},
        "red_flags": {"type": "text"},
        "trust_signals": {"type": "text"},
        "analyzed_at": {"type": "date"},
    }
}


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        logger.warning("Invalid %s value; using %s", name, default)
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        logger.warning("Invalid %s value; using %s", name, default)
        return default


def get_index_name() -> str:
    return os.environ.get("ES_INDEX", DEFAULT_INDEX)


def get_es_client() -> Elasticsearch:
    api_key = os.environ.get("ES_API_KEY")
    if not api_key:
        raise EnvironmentError("ES_API_KEY is not set")
    endpoint = os.environ.get("ES_ENDPOINT", DEFAULT_ES_ENDPOINT)
    if not endpoint:
        raise EnvironmentError("ES_ENDPOINT is not set")
    return Elasticsearch(
        endpoint,
        api_key=api_key,
        request_timeout=_env_float("ES_REQUEST_TIMEOUT", DEFAULT_REQUEST_TIMEOUT),
        max_retries=_env_int("ES_MAX_RETRIES", DEFAULT_MAX_RETRIES),
        retry_on_timeout=False,
    )


def create_index_if_not_exists(
    es: Elasticsearch | None = None,
    *,
    raise_errors: bool = False,
) -> bool:
    try:
        client = es or get_es_client()
        index = get_index_name()
        if not client.indices.exists(index=index):
            client.indices.create(index=index, mappings=INDEX_MAPPINGS)
        return True
    except EnvironmentError:
        if raise_errors:
            raise
        logger.warning("Elasticsearch is not configured")
        return False
    except Exception as e:
        if raise_errors:
            raise EnvironmentError(f"Elasticsearch index setup failed: {e}") from e
        logger.warning("Elasticsearch index setup failed: %s", e)
        return False


def _text_field(value) -> str:
    if isinstance(value, list):
        return "\n".join(str(v) for v in value)
    return str(value) if value is not None else ""


def _doc_from_result(result: dict) -> dict:
    return {
        "url": result["url"],
        "verdict": result["verdict"],
        "score": float(result["score"]),
        "reasons": _text_field(result.get("reasons", [])),
        "red_flags": _text_field(result.get("red_flags", [])),
        "trust_signals": _text_field(result.get("trust_signals", [])),
        "analyzed_at": result.get("analyzed_at")
        or datetime.now(timezone.utc).isoformat(),
    }


def store_result(result: dict, es: Elasticsearch | None = None) -> str | None:
    url = result.get("url", "unknown")
    try:
        client = es or get_es_client()
        if not create_index_if_not_exists(client):
            return None
        response = client.index(index=get_index_name(), document=_doc_from_result(result))
        logger.info("Stored scan result for %s (doc_id=%s)", url, response["_id"])
        return response["_id"]
    except EnvironmentError as e:
        logger.warning(
            "Elasticsearch unavailable, skipping persist for %s: %s",
            url,
            e,
        )
        return None
    except Exception as e:
        logger.warning("Elasticsearch store failed for %s: %s", url, e)
        return None


def search_scams(
    verdict: str | None = None,
    query: str | None = None,
    es: Elasticsearch | None = None,
    *,
    raise_errors: bool = False,
) -> list:
    try:
        client = es or get_es_client()
        if not create_index_if_not_exists(client, raise_errors=raise_errors):
            return []

        must = []
        if verdict:
            must.append({"term": {"verdict": verdict}})
        if query:
            must.append(
                {
                    "multi_match": {
                        "query": query,
                        "fields": ["url", "reasons", "red_flags"],
                    }
                }
            )

        if must:
            es_query = {"bool": {"must": must}}
        else:
            es_query = {"match_all": {}}

        response = client.search(index=get_index_name(), query=es_query, size=10)
        return [hit["_source"] for hit in response["hits"]["hits"]]
    except EnvironmentError:
        if raise_errors:
            raise
        logger.warning("Elasticsearch is not configured")
        return []
    except Exception as e:
        if raise_errors:
            raise EnvironmentError(f"Elasticsearch search failed: {e}") from e
        logger.warning("Elasticsearch search failed: %s", e)
        return []


def get_by_url(
    url: str,
    es: Elasticsearch | None = None,
    *,
    raise_errors: bool = False,
) -> dict | None:
    try:
        client = es or get_es_client()
        if not create_index_if_not_exists(client, raise_errors=raise_errors):
            return None

        response = client.search(
            index=get_index_name(),
            query={"term": {"url": url}},
            size=1,
        )
        hits = response["hits"]["hits"]
        if not hits:
            return None
        logger.debug("Cache hit for %s", url)
        return hits[0]["_source"]
    except EnvironmentError as e:
        if raise_errors:
            raise
        logger.warning(
            "Elasticsearch unavailable, cache miss for %s: %s",
            url,
            e,
        )
        return None
    except Exception as e:
        if raise_errors:
            raise EnvironmentError(f"Elasticsearch lookup failed: {e}") from e
        logger.warning("Elasticsearch lookup failed for %s: %s", url, e)
        return None


if __name__ == "__main__":
    es = get_es_client()
    create_index_if_not_exists(es)

    test_result = {
        "url": "https://www.viagogo.com",
        "verdict": "SUSPICIOUS",
        "score": 5.0,
        "reasons": ["Third-party resale marketplace, not official FIFA ticketing."],
        "red_flags": ["Unofficial reseller"],
        "trust_signals": ["Known brand name"],
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }

    doc_id = store_result(test_result, es)
    print(f"Stored test document: {doc_id}")
    print(f"URL: {test_result['url']}\n")

    print("=" * 60)
    print('Search: verdict = "SUSPICIOUS"')
    print("=" * 60)
    results = search_scams(verdict="SUSPICIOUS", es=es)
    if not results:
        print("(no matches)")
    for i, doc in enumerate(results, 1):
        print(f"\n--- Result {i} ---")
        print(f"URL:     {doc.get('url')}")
        print(f"Verdict: {doc.get('verdict')}")
        print(f"Score:   {doc.get('score')}")
        print(f"Reasons: {doc.get('reasons')}")
