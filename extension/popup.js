/* PhishGuard popup logic. */
const $ = id => document.getElementById(id);

const COLORS = { high: "#ef4444", medium: "#eab308", low: "#22c55e" };
const LABELS = {
  PHISHING: "🚨 PHISHING — KHATARNAK",
  SUSPICIOUS: "⚠️ SHAK WALA LINK",
  "LIKELY SAFE": "✅ ASAL LAGTA HAI",
};

function show(prefix, result) {
  // ids: verdict->'v'+'erdict' trick keeps one code path for both cards
  const map = { v: "verdict", b: "bar", p: "pct", r: "reasons" };
  const get = key => document.getElementById(
    prefix === "m" ? "m" + map[key][0].toUpperCase() + map[key].slice(1) : map[key]);
  const v = get("v");
  v.textContent = LABELS[result.verdict] || result.verdict;
  v.className = "verdict " + result.risk_level;
  const bar = get("b");
  bar.style.width = result.risk_percent + "%";
  bar.style.background = COLORS[result.risk_level];
  get("p").textContent = "Phishing risk: " + result.risk_percent + "%";
  get("r").innerHTML = result.reasons.map(r => "<li>" + r + "</li>").join("");
}

chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
  const url = tabs && tabs[0] ? tabs[0].url : "";
  if (!url || !/^https?:\/\//i.test(url)) {
    $("cur").textContent = "Is page par check lagu nahi hota (browser ki apni page hai).";
    return;
  }
  $("cur").textContent = url;
  try { show("", pgCheck(url)); } catch (e) {
    $("cur").textContent = "Check nahi ho paya: " + e;
  }
});

$("go").onclick = () => {
  const url = $("manual").value.trim();
  if (!url) return;
  $("manualCard").style.display = "block";
  try { show("m", pgCheck(url)); } catch (e) {
    $("mVerdict").textContent = "Check nahi ho paya";
  }
};
$("manual").addEventListener("keydown", e => {
  if (e.key === "Enter") $("go").click();
});
