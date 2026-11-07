/* PhishGuard — URL feature extraction (JavaScript port of features.py).
   Computes the same 27 features from the URL string alone, plus the
   Hindi explanation rules. Requires PG_TOP_DOMAINS (top_domains.js). */

const PG_BRANDS = {
  paypal: "paypal.com", amazon: "amazon.", apple: "apple.com",
  google: "google.", facebook: "facebook.com", instagram: "instagram.com",
  whatsapp: "whatsapp.com", netflix: "netflix.com",
  microsoft: "microsoft.com", sbi: "sbi.co.in", hdfc: "hdfcbank.com",
  icici: "icicibank.com", axis: "axisbank.com", flipkart: "flipkart.com",
  binance: "binance.com", chase: "chase.com", walmart: "walmart.com",
  telegram: "telegram.org", youtube: "youtube.com", twitter: "twitter.com",
  linkedin: "linkedin.com", spotify: "spotify.com", steam: "steampowered.com",
  adobe: "adobe.com", dropbox: "dropbox.com", ebay: "ebay.",
  paytm: "paytm.com", phonepe: "phonepe.com", jio: "jio.com",
};

const PG_SUSPICIOUS_TLDS = new Set([
  "xyz", "top", "click", "zip", "mov", "gq", "cf", "tk", "ml", "work",
  "ooo", "sbs", "icu", "bond", "cyou", "rest", "best", "fans", "live",
  "fun", "site", "online", "store", "buzz", "quest", "space", "today",
]);

const PG_KEYWORDS = [
  "login", "verify", "secure", "account", "update", "confirm", "banking",
  "free", "claim", "prize", "wallet", "password", "signin", "auth",
  "support", "recovery", "suspended", "unlock", "offer", "bonus", "cash",
  "kyc", "otp", "reward",
];

const PG_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "cutt.ly", "is.gd",
  "tiny.cc", "shorturl.at", "rebrand.ly", "short.io", "s.id", "lnkd.in",
  "ow.ly", "buff.ly", "v.gd", "qr.ae", "trib.al", "fold.am",
]);

const PG_HOSTING_PLATFORMS = new Set([
  "blogspot.com", "wordpress.com", "weebly.com", "github.io",
  "netlify.app", "vercel.app", "firebaseapp.com", "web.app",
  "altervista.org", "000webhostapp.com", "wixsite.com", "medium.com",
  "godaddysites.com", "canva.site",
]);

const PG_ABUSED_SUBDOMAINS = new Set(["google.com|sites"]);
const PG_SECOND_LEVEL = new Set([
  "co.in", "ac.in", "co.uk", "com.br", "com.au", "co.jp",
  "com.cn", "co.za", "com.mx", "com.tr", "co.nz", "com.sg",
]);

const PG_IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

function pgParse(url) {
  let u = (url || "").trim();
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(u)) u = "http://" + u;
  try { return new URL(u); } catch (e) { return null; }
}

function pgEntropy(text) {
  if (!text) return 0;
  let h = 0;
  for (const c of new Set(text)) {
    const p = text.split(c).length - 1;
    const prob = p / text.length;
    h -= prob * Math.log2(prob);
  }
  return h;
}

function pgRegistrable(host) {
  const labels = host.split(".");
  if (labels.length <= 2) return host;
  const tail2 = labels.slice(-2).join(".");
  if (PG_SECOND_LEVEL.has(tail2)) return labels.slice(-3).join(".");
  return tail2;
}

function pgRankBucket(host) {
  const ranks = (typeof PG_TOP_DOMAINS !== "undefined") ? PG_TOP_DOMAINS : {};
  const h = (host || "").toLowerCase();
  let rank = ranks[h];
  if (rank === undefined) {
    const reg = pgRegistrable(h);
    const extra = h.endsWith("." + reg) ? h.slice(0, -(reg.length + 1)) : "";
    if (ranks[reg] !== undefined) {
      if (extra === "" || extra === "www" || extra === "m") {
        rank = ranks[reg];
      } else if (!extra.includes(".") && ranks[reg] <= 1000 &&
                 !PG_HOSTING_PLATFORMS.has(reg) &&
                 !PG_ABUSED_SUBDOMAINS.has(reg + "|" + extra)) {
        rank = ranks[reg];
      }
    }
  }
  if (rank === undefined) return 3;
  if (rank <= 1000) return 0;
  if (rank <= 10000) return 1;
  return 2;
}

function pgBrandFlags(host, rest) {
  const hostL = host.toLowerCase(), restL = rest.toLowerCase();
  let inHost = 0, inPath = 0;
  for (const brand of Object.keys(PG_BRANDS)) {
    const real = PG_BRANDS[brand];
    if (hostL.includes(brand) && !hostL.includes(real)) inHost = 1;
    if (restL.includes(brand) && !hostL.includes(brand)) inPath = 1;
  }
  return [inHost, inPath];
}

function pgExtractFeatures(url) {
  const p = pgParse(url);
  const raw = url || "";
  const host = p ? (p.hostname || "").toLowerCase() : "";
  const full = raw.toLowerCase();
  const path = p ? (p.pathname || "") : "";
  const query = p ? (p.search ? p.search.slice(1) : "") : "";
  const rest = path + "?" + query;

  const labels = host ? host.split(".") : [];
  const tld = labels.length ? labels[labels.length - 1] : "";
  const subdomains = labels.length > 2 ? labels.length - 2 : 0;
  const digits = (full.match(/\d/g) || []).length;
  const [brandHost, brandPath] = pgBrandFlags(host, rest);
  const keywordCount = PG_KEYWORDS.filter(k => full.includes(k)).length;

  return {
    url_length: raw.length,
    hostname_length: host.length,
    path_length: path.length,
    num_dots_host: (host.match(/\./g) || []).length,
    num_hyphens_host: (host.match(/-/g) || []).length,
    num_digits_host: (host.match(/\d/g) || []).length,
    has_ip_host: PG_IP_RE.test(host) ? 1 : 0,
    num_subdomains: subdomains,
    is_https: p && p.protocol === "https:" ? 1 : 0,
    has_at_symbol: raw.includes("@") ? 1 : 0,
    has_double_slash_path: path.includes("//") ? 1 : 0,
    num_query_params: query ? (query.match(/&/g) || []).length + 1 : 0,
    has_port: p && p.port ? 1 : 0,
    suspicious_tld: PG_SUSPICIOUS_TLDS.has(tld) ? 1 : 0,
    brand_in_host: brandHost,
    brand_in_path: brandPath,
    keyword_count: keywordCount,
    entropy_host: Math.round(pgEntropy(host) * 1000) / 1000,
    digit_ratio_url: full.length ? Math.round((digits / full.length) * 1000) / 1000 : 0,
    num_percent: (raw.match(/%/g) || []).length,
    num_underscore: (raw.match(/_/g) || []).length,
    is_shortener: PG_SHORTENERS.has(host) ? 1 : 0,
    has_punycode: host.includes("xn--") ? 1 : 0,
    https_in_text: (host.includes("https") || path.toLowerCase().includes("https")) ? 1 : 0,
    tld_length: tld.length,
    special_char_count: (raw.match(/[^a-zA-Z0-9./:]/g) || []).length,
    domain_rank_bucket: pgRankBucket(host),
  };
}

function pgExplain(url) {
  const p = pgParse(url);
  const host = p ? (p.hostname || "").toLowerCase() : "";
  const f = pgExtractFeatures(url);
  const reasons = [];
  if (f.has_ip_host) reasons.push("Domain ki jagah seedha IP address use ho raha hai — asli companies aisa kabhi nahi karti.");
  if (f.brand_in_host) reasons.push("Naam kisi badi brand jaisa hai, lekin domain us brand ka asal domain nahi hai — nakal ki koshish lagti hai.");
  if (f.brand_in_path) reasons.push("Link ke andar kisi brand ka naam istemal hai, jabki website khud kisi aur ki hai.");
  if (f.suspicious_tld) {
    const tld = host.includes(".") ? host.split(".").pop() : "";
    reasons.push("Domain ka ant (." + tld + ") saste/abuse ke liye badnaam extension me hai — phishing me bahut common hai.");
  }
  if (f.is_https === 0) reasons.push("HTTPS nahi hai — connection surakshit nahi hai; asli bank/login sites hamesha HTTPS hoti hain.");
  if (f.has_at_symbol) reasons.push("Link me '@' hai — browser '@' se pehle wala hissa ignore kar deta hai; ye purani chhupane wali trick hai.");
  if (f.num_subdomains >= 3) reasons.push("Bahut saare subdomains (" + f.num_subdomains + ") — asli naam ko beech me chhupaya gaya lagta hai.");
  if (f.keyword_count >= 3) reasons.push("Link me login/verify/claim type ke dabav wale shabd kai baar aaye hain.");
  if (f.is_shortener) reasons.push("Ye ek URL shortener hai — asli destination chhupa hua hai, kholne se pehle jaanch zaroori hai.");
  if (f.has_punycode) reasons.push("Punycode domain hai — akshar dusri bhasha ke nakli aksharo se milte-julte ho sakte hain.");
  if (f.has_port) reasons.push("Link me alag port number hai — aam websites me aisa nahi hota.");
  if (f.url_length >= 90) reasons.push("Link bahut lamba hai (" + f.url_length + " characters) — phishing links aksar lambe aur uljhe hue hote hain.");
  if (f.entropy_host >= 4.2) reasons.push("Domain ka naam ajeeb/ulti-seedhi aksharo wala lagta hai — machine se banaya gaya ho sakta hai.");
  return reasons;
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { pgExtractFeatures, pgExplain, pgRankBucket };
}
