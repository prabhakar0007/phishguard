"""
PhishGuard — URL feature extraction.

Turns a raw URL into a fixed vector of lexical features used by the ML
model, and can also produce human-readable warning reasons for a URL
(used by the web UI to explain a verdict).

Everything here is computed from the URL string alone — no network calls —
so training and live prediction always see identical features.
"""

import math
import re
from urllib.parse import urlparse

# Brands most commonly impersonated by phishing pages, with one real domain
# each (a brand word on any OTHER domain is a red flag).
BRANDS = {
    "paypal": "paypal.com", "amazon": "amazon.", "apple": "apple.com",
    "google": "google.", "facebook": "facebook.com", "instagram": "instagram.com",
    "whatsapp": "whatsapp.com", "netflix": "netflix.com",
    "microsoft": "microsoft.com", "sbi": "sbi.co.in", "hdfc": "hdfcbank.com",
    "icici": "icicibank.com", "axis": "axisbank.com", "flipkart": "flipkart.com",
    "binance": "binance.com", "chase": "chase.com", "walmart": "walmart.com",
    "telegram": "telegram.org", "youtube": "youtube.com", "twitter": "twitter.com",
    "linkedin": "linkedin.com", "spotify": "spotify.com", "steam": "steampowered.com",
    "adobe": "adobe.com", "dropbox": "dropbox.com", "ebay": "ebay.",
    "paytm": "paytm.com", "phonepe": "phonepe.com", "jio": "jio.com",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "zip", "mov", "gq", "cf", "tk", "ml", "work",
    "ooo", "sbs", "icu", "bond", "cyou", "rest", "best", "fans", "live",
    "fun", "site", "online", "store", "buzz", "quest", "space", "today",
}

KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm", "banking",
    "free", "claim", "prize", "wallet", "password", "signin", "auth",
    "support", "recovery", "suspended", "unlock", "offer", "bonus", "cash",
    "kyc", "otp", "reward",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "cutt.ly", "is.gd",
    "tiny.cc", "shorturl.at", "rebrand.ly", "short.io", "s.id", "lnkd.in",
    "ow.ly", "buff.ly", "v.gd", "qr.ae", "rb.gy", "trib.al", "fold.am",
}

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# --- Domain popularity (Tranco) -------------------------------------------
# Real anti-phishing systems use domain reputation as one signal. We ship
# the Tranco top-100k as data/top_domains.csv and bucket the rank:
#   0 = top 1k, 1 = top 10k, 2 = top 100k, 3 = not listed / unknown.
# A subdomain only inherits the parent domain's rank when its extra label
# is a harmless one (www / m) — so phishing pages hosted as subdomains of
# blogspot.com & friends do NOT inherit blogspot's popularity.
from pathlib import Path as _Path

_RANKS = None
_SECOND_LEVEL = {"co.in", "ac.in", "co.uk", "com.br", "com.au", "co.jp",
                 "com.cn", "co.za", "com.mx", "com.tr", "co.nz", "com.sg"}


def _load_ranks():
    global _RANKS
    if _RANKS is None:
        _RANKS = {}
        path = _Path(__file__).parent / "top_domains.csv"
        if path.exists():
            import csv as _csv
            with open(path, encoding="utf-8") as fh:
                for row in _csv.reader(fh):
                    if len(row) >= 2:
                        try:
                            _RANKS[row[1].strip().lower()] = int(row[0])
                        except ValueError:
                            pass
    return _RANKS


def _registrable(host: str) -> str:
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    tail2 = ".".join(labels[-2:])
    if tail2 in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return tail2


# Platforms where ANYONE can host a page as a subdomain — their subdomains
# must never inherit the platform's popularity (phishing abuses these).
HOSTING_PLATFORMS = {
    "blogspot.com", "wordpress.com", "weebly.com", "github.io",
    "netlify.app", "vercel.app", "firebaseapp.com", "web.app",
    "altervista.org", "000webhostapp.com", "wixsite.com", "medium.com",
    "godaddysites.com", "canva.site",
}
# Specific abused subdomains of otherwise trusted domains.
ABUSED_SUBDOMAINS = {("google.com", "sites")}


def domain_rank_bucket(host: str) -> int:
    ranks = _load_ranks()
    h = host.lower()
    rank = ranks.get(h)
    if rank is None:
        reg = _registrable(h)
        extra = h[: -(len(reg) + 1)] if h.endswith("." + reg) else ""
        if reg in ranks:
            if extra in ("", "www", "m"):
                rank = ranks[reg]
            elif ("." not in extra and ranks[reg] <= 1_000
                    and reg not in HOSTING_PLATFORMS
                    and (reg, extra) not in ABUSED_SUBDOMAINS):
                # e.g. en.wikipedia.org, docs.google.com — language and
                # service subdomains of the world's top domains.
                rank = ranks[reg]
    if rank is None:
        return 3
    if rank <= 1_000:
        return 0
    if rank <= 10_000:
        return 1
    return 2


def _parse(url: str):
    u = (url or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
        u = "http://" + u
    return urlparse(u)


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {c: text.count(c) / len(text) for c in set(text)}
    return -sum(p * math.log2(p) for p in freq.values())


def _brand_flags(host: str, rest: str):
    """Return (brand_in_host, brand_in_path) impersonation flags."""
    host_l = host.lower()
    rest_l = rest.lower()
    in_host = 0
    in_path = 0
    for brand, real in BRANDS.items():
        if brand in host_l and real not in host_l:
            in_host = 1
        if brand in rest_l:
            # brand word used in the path/query of an unrelated host
            if brand not in host_l:
                in_path = 1
    return in_host, in_path


def extract_features(url: str) -> dict:
    """Return the ordered feature dict for one URL."""
    p = _parse(url)
    host = (p.hostname or "").lower()
    full = (url or "").lower()
    path = p.path or ""
    query = p.query or ""
    rest = path + "?" + query

    labels = host.split(".") if host else []
    tld = labels[-1] if labels else ""
    subdomains = max(0, len(labels) - 2) if len(labels) > 2 else 0
    digits = sum(c.isdigit() for c in full)
    brand_host, brand_path = _brand_flags(host, rest)
    keyword_count = sum(1 for k in KEYWORDS if k in full)

    feats = {
        "url_length": len(url or ""),
        "hostname_length": len(host),
        "path_length": len(path),
        "num_dots_host": host.count("."),
        "num_hyphens_host": host.count("-"),
        "num_digits_host": sum(c.isdigit() for c in host),
        "has_ip_host": 1 if IP_RE.match(host) else 0,
        "num_subdomains": subdomains,
        "is_https": 1 if p.scheme == "https" else 0,
        "has_at_symbol": 1 if "@" in (url or "") else 0,
        "has_double_slash_path": 1 if "//" in path else 0,
        "num_query_params": query.count("&") + 1 if query else 0,
        "has_port": 1 if p.port else 0,
        "suspicious_tld": 1 if tld in SUSPICIOUS_TLDS else 0,
        "brand_in_host": brand_host,
        "brand_in_path": brand_path,
        "keyword_count": keyword_count,
        "entropy_host": round(_entropy(host), 3),
        "digit_ratio_url": round(digits / len(full), 3) if full else 0.0,
        "num_percent": (url or "").count("%"),
        "num_underscore": (url or "").count("_"),
        "is_shortener": 1 if host in SHORTENERS else 0,
        "has_punycode": 1 if "xn--" in host else 0,
        "https_in_text": 1 if ("https" in host or "https" in path.lower()) else 0,
        "tld_length": len(tld),
        "special_char_count": len(re.findall(r"[^a-zA-Z0-9./:]", url or "")),
        "domain_rank_bucket": domain_rank_bucket(host),
    }
    return feats


FEATURE_NAMES = list(extract_features("https://example.com/").keys())


def feature_vector(url: str) -> list:
    feats = extract_features(url)
    return [feats[name] for name in FEATURE_NAMES]


def explain(url: str) -> list:
    """Human-readable warning signs found in this URL (for the UI)."""
    p = _parse(url)
    host = (p.hostname or "").lower()
    f = extract_features(url)
    reasons = []

    if f["has_ip_host"]:
        reasons.append("Domain ki jagah seedha IP address use ho raha hai — "
                       "asli companies aisa kabhi nahi karti.")
    if f["brand_in_host"]:
        reasons.append("Naam kisi badi brand jaisa hai, lekin domain us brand "
                       "ka asal domain nahi hai — nakal ki koshish lagti hai.")
    if f["brand_in_path"]:
        reasons.append("Link ke andar kisi brand ka naam istemal hai, jabki "
                       "website khud kisi aur ki hai.")
    if f["suspicious_tld"]:
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        reasons.append(f"Domain ka ant (.{tld}) saste/abuse ke liye badnaam "
                       "extension me hai — phishing me bahut common hai.")
    if f["is_https"] == 0:
        reasons.append("HTTPS nahi hai — connection surakshit nahi hai; "
                       "asli bank/login sites hamesha HTTPS hoti hain.")
    if f["has_at_symbol"]:
        reasons.append("Link me '@' hai — browser '@' se pehle wala hissa "
                       "ignore kar deta hai; ye purani chhupane wali trick hai.")
    if f["num_subdomains"] >= 3:
        reasons.append(f"Bahut saare subdomains ({f['num_subdomains']}) — "
                       "asli naam ko beech me chhupaya gaya lagta hai.")
    if f["keyword_count"] >= 3:
        reasons.append("Link me login/verify/claim type ke dabav wale shabd "
                       "kai baar aaye hain.")
    if f["is_shortener"]:
        reasons.append("Ye ek URL shortener hai — asli destination chhupa "
                       "hua hai, kholne se pehle jaanch zaroori hai.")
    if f["has_punycode"]:
        reasons.append("Punycode domain hai — akshar dusri bhasha ke nakli "
                       "aksharo se milte-julte ho sakte hain.")
    if f["has_port"]:
        reasons.append("Link me alag port number hai — aam websites me aisa "
                       "nahi hota.")
    if f["url_length"] >= 90:
        reasons.append(f"Link bahut lamba hai ({f['url_length']} characters) — "
                       "phishing links aksar lambe aur uljhe hue hote hain.")
    if f["entropy_host"] >= 4.2:
        reasons.append("Domain ka naam ajeeb/ulti-seedhi aksharo wala lagta "
                       "hai — machine se banaya gaya ho sakta hai.")
    return reasons
