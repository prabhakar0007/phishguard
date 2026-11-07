/* PhishGuard — in-browser model engine.
   Walks the exported RandomForest (model.js) over the features from
   features.js. Same verdict thresholds as the server app:
   >= 0.65 PHISHING, >= 0.40 SUSPICIOUS, else LIKELY SAFE. */

function pgPredictProba(url) {
  const feats = pgExtractFeatures(url);
  const order = PG_MODEL.features;
  const x = order.map(name => feats[name]);
  let sum = 0;
  for (const tree of PG_MODEL.trees) {
    let node = 0;
    while (tree.l[node] !== -1) {
      node = x[tree.f[node]] <= tree.th[node] ? tree.l[node] : tree.r[node];
    }
    sum += tree.p[node];
  }
  return sum / PG_MODEL.trees.length;
}

function pgCheck(url) {
  const prob = pgPredictProba(url);
  let reasons = pgExplain(url);
  let verdict, level;
  if (prob >= 0.65) {
    verdict = "PHISHING"; level = "high";
    if (!reasons.length) reasons = ["Model ko is link ke kai patterns phishing jaise lage hain."];
  } else if (prob >= 0.40) {
    verdict = "SUSPICIOUS"; level = "medium";
    if (!reasons.length) reasons = ["Kuch patterns ajeeb hain — bina jaanch ke login ya payment mat karo."];
  } else {
    verdict = "LIKELY SAFE"; level = "low";
    if (!reasons.length) reasons = ["Koi bada khatre wala pattern nahi mila. Phir bhi, anjaan link par hamesha dhyaan do."];
  }
  return {
    url, verdict, risk_level: level,
    phishing_probability: Math.round(prob * 10000) / 10000,
    risk_percent: Math.round(prob * 1000) / 10,
    reasons,
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { pgCheck, pgPredictProba };
}
