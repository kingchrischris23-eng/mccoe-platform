"""Quick IOC count and optional feed refresh."""
import sys

from src.feeds.aggregator import refresh_feeds
from src.storage.repository import count_iocs_filtered, init_db, list_iocs_filtered, save_iocs


def main(refresh: bool = False) -> None:
    init_db()
    if refresh:
        result = refresh_feeds(force_refresh=True)
        save_iocs(result.iocs)
        print(f"Refreshed {result.total:,} IOC(s) from feeds.")
        for src in result.sources:
            print(f"  {src.name}: {src.count:,}" + (f" — {src.error}" if src.error else ""))

    total = count_iocs_filtered()
    nist = count_iocs_filtered(source="NIST NVD")
    cisa = count_iocs_filtered(source="CISA KEV")
    page1 = list_iocs_filtered(limit=50, sort="newest")
    print(f"Total: {total:,} | NIST NVD: {nist:,} | CISA KEV: {cisa:,} | Page 1: {len(page1)}")


if __name__ == "__main__":
    main(refresh="--refresh" in sys.argv)