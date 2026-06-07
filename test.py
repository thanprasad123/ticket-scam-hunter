from elasticsearch import Elasticsearch
import os

es = Elasticsearch(
    "https://697bbb480339473190e87012c2d7d8f4.us-central1.gcp.cloud.es.io:443",
    api_key=os.environ.get("ES_API_KEY")
)

try:
    info = es.info()
    print("✅ Connected!", info)
except Exception as e:
    print(f"❌ Error: {e}")
