import time
import tracemalloc
from datetime import datetime, timedelta

from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan

# CONFIG – adapt if your ES URL is different
ES_URL = "http://greedybear-elasticsearch-1:9200"
INDEX = "logstash-2026.01.20"  # the index you already created
MINUTES_BACK = 60 * 24 * 3  # last 3 days, to match synthetic docs


def query_body(minutes_back: int):
    now = datetime.utcnow()
    since = now - timedelta(minutes=minutes_back)
    return {"query": {"range": {"@timestamp": {"gte": since.isoformat(), "lte": now.isoformat()}}}, "sort": [{"@timestamp": {"order": "asc"}}]}


def run_list_strategy(es: Elasticsearch):
    print("=== LIST STRATEGY (current behavior) ===")
    body = query_body(MINUTES_BACK)

    tracemalloc.start()
    t0 = time.time()

    # Mimic `search.scan()` → list(...)
    results = list(
        scan(
            es,
            index=INDEX,
            query=body,
        )
    )

    t1 = time.time()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print(f"Docs loaded: {len(results)}")
    print(f"Time: {t1 - t0:.2f}s")
    print(f"Peak Python heap (bytes): {peak}")

    # Mimic sort by @timestamp
    results.sort(key=lambda hit: hit["_source"]["@timestamp"])

    # Mimic grouping by honeypot (type)
    hits_by_honeypot = {}
    for hit in results:
        hp = hit["_source"].get("type", "unknown")
        hits_by_honeypot.setdefault(hp, []).append(hit)

    print("Honeypots:", {k: len(v) for k, v in hits_by_honeypot.items()})


def run_iterator_strategy(es: Elasticsearch):
    print("=== ITERATOR STRATEGY (no list, no cache) ===")
    body = query_body(MINUTES_BACK)

    tracemalloc.start()
    t0 = time.time()

    # Directly scan and process stream, without keeping full list
    hits_by_honeypot = {}
    count = 0
    for hit in scan(es, index=INDEX, query=body):
        count += 1
        hp = hit["_source"].get("type", "unknown")
        hits_by_honeypot.setdefault(hp, []).append(hit)

    t1 = time.time()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print(f"Docs processed: {count}")
    print(f"Time: {t1 - t0:.2f}s")
    print(f"Peak Python heap (bytes): {peak}")
    print("Honeypots:", {k: len(v) for k, v in hits_by_honeypot.items()})


def main():
    es = Elasticsearch(ES_URL)
    print("Connected to ES:", es.info().body.get("version", {}))

    run_list_strategy(es)
    print()
    run_iterator_strategy(es)


if __name__ == "__main__":
    main()
