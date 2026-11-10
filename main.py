import csv
import io
from pathlib import Path
from urllib.request import urlopen

BLACKLIST_URL = (
    "https://raw.githubusercontent.com/ziyadnz/threat-intel-ip-feeds/"
    "refs/heads/main/output/blacklist.csv"
)

with urlopen(BLACKLIST_URL) as response:
    with io.TextIOWrapper(response, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        multi_source = [
            r
            for r in reader
            if r["type"] == "ipv4" and int(r["source_count"]) > 2
        ]

output_path = Path("output/multi_source.csv")
output_path.parent.mkdir(parents=True, exist_ok=True)
with output_path.open("w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(multi_source)

print(f"{len(multi_source)} IPs flagged by 3+ sources")
print(f"Exported to {output_path}")