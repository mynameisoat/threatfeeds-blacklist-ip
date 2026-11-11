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
        multi_source = [
            r
            for r in reader
            if r["type"] == "ipv4" and int(r["source_count"]) > 3
        ]

output_path = Path("output/multi_source.txt")
output_path.parent.mkdir(parents=True, exist_ok=True)
with output_path.open("w", encoding="utf-8") as f:
    f.writelines(f'{r["ip"]}\n' for r in multi_source)
