"""Store and retrieve Ticket Scam Hunter scan results in Elasticsearch."""

import logging
import os
from datetime import datetime, timezone

from elasticsearch import Elasticsearch

logger = logging.getLogger(__name__)

ES_ENDPOINT = (
    "https://697bbb480339473190e87012c2d7d8f4.us-central1.gcp.cloud.es.io:443"
)
INDEX = "scam-sites"

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


def get_es_client() -> Elasticsearch:
    api_key = os.environ.get("ES_API_KEY")
    if not api_key:
        raise EnvironmentError("ES_API_KEY is not set")
    return Elasticsearch(ES_ENDPOINT, api_key=api_key)


def create_index_if_not_exists(es: Elasticsearch | None = None) -> None:
    try:
        client = es or get_es_client()
        if not client.indices.exists(index=INDEX):
            client.indices.create(index=INDEX, mappings=INDEX_MAPPINGS)
    except Exception as e:
        logger.warning("Elasticsearch index setup failed: %s", e)


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
        create_index_if_not_exists(client)
        response = client.index(index=INDEX, document=_doc_from_result(result))
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
) -> list:
    try:
        client = es or get_es_client()
        create_index_if_not_exists(client)

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

        response = client.search(index=INDEX, query=es_query, size=10)
        return [hit["_source"] for hit in response["hits"]["hits"]]
    except Exception as e:
        logger.warning("Elasticsearch search failed: %s", e)
        return []


def get_by_url(url: str, es: Elasticsearch | None = None) -> dict | None:
    try:
        client = es or get_es_client()
        create_index_if_not_exists(client)

        response = client.search(
            index=INDEX,
            query={"term": {"url": url}},
            size=1,
        )
        hits = response["hits"]["hits"]
        if not hits:
            return None
        logger.debug("Cache hit for %s", url)
        return hits[0]["_source"]
    except EnvironmentError as e:
        logger.warning(
            "Elasticsearch unavailable, cache miss for %s: %s",
            url,
            e,
        )
        return None
    except Exception as e:
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
