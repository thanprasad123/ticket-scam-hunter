import unittest
from unittest.mock import patch

from schemas import ScanUrlRequest, UrlFetchError, Verdict
from scanner import scan_ticket_url


class TestScanTicketUrl(unittest.IsolatedAsyncioTestCase):
    async def test_cached_scan_returns_cached_document(self):
        cached_doc = {
            "url": "https://example.com",
            "verdict": "SCAM",
            "score": 8.0,
            "reasons": ["Fake FIFA ticket offer."],
            "red_flags": ["Urgent payment demand."],
            "trust_signals": ["SSL certificate present."],
            "analyzed_at": "2026-01-01T00:00:00Z",
        }

        with patch("scanner.get_by_url", return_value=cached_doc):
            request = ScanUrlRequest(
                url="https://example.com",
                persist=False,
                force_refresh=False,
            )
            response = await scan_ticket_url(request)

        self.assertTrue(response.cached)
        self.assertEqual(response.url, "https://example.com")
        self.assertEqual(response.verdict, Verdict.SCAM)
        self.assertEqual(response.score, 8.0)
        self.assertEqual(response.reasons, ["Fake FIFA ticket offer."])

    async def test_scan_ticket_url_raises_url_fetch_error_on_fetch_failure(self):
        with patch("scanner._fetch_page_with_retry", side_effect=UrlFetchError("Failed to fetch URL.")):
            request = ScanUrlRequest(
                url="https://example.com",
                persist=False,
                force_refresh=True,
            )
            with self.assertRaises(UrlFetchError):
                await scan_ticket_url(request)
