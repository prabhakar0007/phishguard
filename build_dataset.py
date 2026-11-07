#!/usr/bin/env python3
"""
Build data/dataset.csv from REAL sources:

  Phishing (label 1):
    - OpenPhish community feed        (data/openphish.txt)
    - Phishing.Database ACTIVE list   (data/phishingdb.txt)
    Download: https://openphish.com/feed.txt
              https://raw.githubusercontent.com/mitchellkrogza/
              Phishing.Database/master/phishing-links-ACTIVE.txt

  Legitimate (label 0):
    - Tranco top-sites ranking        (data/tranco.zip -> top-1m.csv)
    Download: https://tranco-list.eu/top-1m.csv.zip
    URL strings are built from the real ranked domains (bare domain,
    www. form, or with a common generic path) — the standard way lexical
    URL datasets are assembled.

Run:  python3 build_dataset.py
"""

import csv
import io
import random
import zipfile
from pathlib import Path

random.seed(42)
DATA = Path(__file__).parent / "data"
N_PHISH = 6000
N_LEGIT = 6000
GENERIC_PATHS = ["/", "/index.html", "/about", "/products", "/blog",
                 "/en", "/home", "/shop", "/news", "/contact"]

# Real-world style full-URL shapes seen on top sites (articles, products,
# videos, search...). Used ONLY as path templates on real Tranco domains so
# the model learns that long, messy URLs are normal on legitimate sites too
# (without this, any long real URL looks "phishing" to the model).
WORDS = ["online", "safety", "guide", "best", "india", "new", "top", "how",
         "what", "learn", "free", "home", "2026", "review", "tips", "story",
         "world", "tech", "phone", "price", "offer", "sale", "book", "music",
         "video", "photo", "travel", "food", "health", "study", "exam",
         "result", "job", "news", "live", "watch", "play", "read", "shop"]
SLUG = lambda: "-".join(random.sample(WORDS, random.randint(2, 5)))  # noqa: E731
PATH_TEMPLATES = [
    lambda d: f"/wiki/{SLUG().title().replace('-', '_')}",
    lambda d: f"/blog/{SLUG()}",
    lambda d: f"/news/{SLUG()}-{random.randint(100000, 999999)}",
    lambda d: f"/article/{SLUG()}",
    lambda d: f"/products/{SLUG()}/{random.randint(10000, 99999)}",
    lambda d: f"/dp/B0{random.randint(10000000, 99999999)}",
    lambda d: f"/item/{random.randint(100000, 999999)}",
    lambda d: f"/watch?v={random.randint(10000000, 99999999)}aB",
    lambda d: f"/search?q={'+'.join(random.sample(WORDS, 2))}",
    lambda d: f"/help/account/{SLUG()}",
    lambda d: f"/2026/11/{SLUG()}",
    lambda d: f"/en/{SLUG()}?page={random.randint(1, 9)}",
]


def load_phishing() -> list:
    urls = set()
    for name in ("openphish.txt", "phishingdb.txt"):
        path = DATA / name
        if not path.exists():
            print(f"  (missing {name}, skipped)")
            continue
        for line in path.read_text(errors="ignore").splitlines():
            u = line.strip()
            if u.startswith(("http://", "https://")) and len(u) > 12:
                urls.add(u)
    urls = sorted(urls)
    random.shuffle(urls)
    print(f"  phishing pool: {len(urls)} unique http(s) URLs")
    return urls[:N_PHISH]


def load_legit() -> list:
    urls = []
    with zipfile.ZipFile(DATA / "tranco.zip") as zf:
        name = zf.namelist()[0]
        with zf.open(name) as fh:
            rows = list(csv.reader(io.TextIOWrapper(fh, encoding="utf-8")))
    domains = [r[1].strip() for r in rows[:200_000] if len(r) >= 2]
    top_domains = [r[1].strip() for r in rows[:400] if len(r) >= 2]
    random.shuffle(domains)
    for d in domains[: int(N_LEGIT * 0.40)]:
        r = random.random()
        if r < 0.6:
            urls.append(f"https://{d}")
        elif r < 0.85:
            urls.append(f"https://www.{d}")
        else:
            urls.append(f"https://{d}{random.choice(GENERIC_PATHS)}")
    # Full, messy, real-world-shaped URLs on the most popular domains
    for _ in range(N_LEGIT - len(urls)):
        d = random.choice(top_domains)
        www = "www." if random.random() < 0.5 else ""
        urls.append(f"https://{www}{d}{random.choice(PATH_TEMPLATES)(d)}")
    print(f"  legit pool: {len(urls)} URLs built from Tranco domains")
    return urls


def write_top_domains() -> None:
    """Ship the Tranco top-100k (rank,domain) for the rank feature."""
    with zipfile.ZipFile(DATA / "tranco.zip") as zf:
        name = zf.namelist()[0]
        with zf.open(name) as fh:
            rows = list(csv.reader(io.TextIOWrapper(fh, encoding="utf-8")))
    out = DATA.parent / "top_domains.csv"
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        for r in rows[:100_000]:
            if len(r) >= 2:
                w.writerow([r[0], r[1]])
    print(f"  wrote {out} (top 100k domains)")


def main() -> None:
    write_top_domains()
    phish = load_phishing()
    legit = load_legit()
    rows = [(u, 1) for u in phish] + [(u, 0) for u in legit]
    random.shuffle(rows)
    out = DATA.parent / "dataset.csv"
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "label"])
        w.writerows(rows)
    print(f"Wrote {out}: {len(rows)} rows "
          f"({len(phish)} phishing, {len(legit)} legit)")


if __name__ == "__main__":
    main()
