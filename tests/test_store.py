import unittest

from store import search_scams


class DummyIndices:
    def __init__(self, exists=True):
        self._exists = exists
        self.created = False

    def exists(self, index):
        return self._exists

    def create(self, index, mappings=None):
        self.created = True


class DummyClient:
    def __init__(self):
        self.indices = DummyIndices(exists=True)
        self.last_query = None

    def search(self, index, query, size):
        self.last_query = (index, query, size)
        return {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "url": "https://example.com",
                            "verdict": "SCAM",
                            "score": 9.0,
                            "reasons": "Cheap tickets and fake guarantee.",
                            "red_flags": "Pressure sales",
                            "trust_signals": "None",
                            "analyzed_at": "2026-01-01T00:00:00Z",
                        }
                    }
                ]
            }
        }


class TestSearchScams(unittest.TestCase):
    def test_search_scams_returns_results_for_verdict_and_query(self):
        client = DummyClient()
        results = search_scams(verdict="SCAM", query="cheap", es=client)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["url"], "https://example.com")
        self.assertEqual(results[0]["verdict"], "SCAM")
        self.assertEqual(client.last_query[0], "scam-sites")
        self.assertEqual(client.last_query[2], 10)
        self.assertIn("bool", client.last_query[1])
