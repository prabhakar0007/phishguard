# PhishGuard — ML Phishing URL Detector

A machine-learning system that checks any link and tells you whether it
looks **legitimate or phishing** — with a risk score and plain-language
reasons for the verdict. Comes with a web UI and a JSON API.

> **Stage 1** (model + website) and **Stage 2** (Chrome extension, in
> [`extension/`](extension/)) are both complete. The extension runs the
> model entirely inside the browser and blocks phishing pages *before*
> they load.

## Results (honest, held-out test set)

Trained on **12,000 real URLs** and tested on 2,400 URLs the model never
saw during training:

| Metric | Score |
|---|---|
| Accuracy | **96.5%** |
| Precision (phishing) | 97.1% |
| Recall (phishing) | 96.0% |
| F1 | 0.965 |

## Data sources (all real, all public)

- **Phishing:** [OpenPhish](https://openphish.com) community feed +
  [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database)
  active phishing links (789k pool, 6,000 sampled)
- **Legitimate:** [Tranco](https://tranco-list.eu) top-sites ranking —
  bare domains, `www.` forms, and full real-world-shaped URLs (articles,
  products, search...) built on the ranked domains. Early testing showed
  that training only on bare domains makes the model flag every long real
  URL as phishing; the full-URL shapes fixed that.

## How it works

1. **Feature extraction** (`features.py`) — 27 signals from the URL alone:
   length/structure, IP-as-host, `@` tricks, subdomains, suspicious TLDs,
   brand impersonation (a brand name on a domain that isn't the brand's),
   pressure keywords (login / verify / claim / KYC...), URL shorteners,
   punycode, hostname entropy — plus **domain popularity** from the Tranco
   top-100k, the same kind of reputation signal real anti-phishing systems
   use. Subdomains only inherit a parent domain's popularity in safe cases,
   so phishing hosted on blogspot.com & similar platforms is *not*
   whitewashed by the platform's rank.
2. **Model** (`train_model.py`) — RandomForest (300 trees), stratified
   80/20 split, metrics printed before saving. Model bundle:
   `phishguard_model.joblib`; numbers: `metrics.json`.
3. **Web app** (`app.py`) — Flask UI + API. Every verdict includes
   human-readable reasons (e.g. "brand name on a non-brand domain",
   "IP address instead of a domain", "suspicious .xyz extension").

## Run it

```bash
pip install -r requirements.txt
python3 app.py            # http://127.0.0.1:5000
```

Try the example chips in the UI, or use the API:

```bash
curl -X POST localhost:5000/api/check \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://paypal-secure-login.xyz/verify"}'
```

## Retrain from scratch

```bash
# 1) download the raw sources into data/ (links in build_dataset.py)
# 2) build the dataset + top-100k list
python3 build_dataset.py
# 3) train and evaluate
python3 train_model.py
```

## Project layout

```
app.py                  Flask web app (UI + /api/check + /api/metrics)
features.py             URL feature extraction + explanation rules
build_dataset.py        Builds dataset.csv from the real sources
train_model.py          Trains + honestly evaluates the model
index.html              Web UI (Flask template)
phishguard_model.joblib Trained model bundle
metrics.json            Measured test metrics
dataset.csv             12,000 labelled URLs (6k phishing / 6k legit)
top_domains.csv         Tranco top-100k (rank, domain) for the rank feature
data/                   Raw downloads go here (not in the repo)
```

## ⚠️ Disclaimer

A detector reduces risk; it is not a guarantee. No model is 100%
accurate — always check the real domain before entering passwords or
payment details. Built for education and defensive use.

## License

MIT — see [LICENSE](LICENSE).
