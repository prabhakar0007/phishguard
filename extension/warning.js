/* PhishGuard warning page logic. */
const params = new URLSearchParams(location.search);
const original = params.get("url") || "";
const risk = params.get("risk") || "?";

document.getElementById("url").textContent = original;
document.getElementById("risk").textContent = risk + "%";

try {
  const result = pgCheck(original);
  document.getElementById("reasons").innerHTML =
    result.reasons.map(r => "<li>" + r + "</li>").join("");
} catch (e) { /* reasons are a bonus; the warning itself is what matters */ }

document.getElementById("back").onclick = () => {
  if (history.length > 1) history.back();
  else location.href = "https://www.google.com";
};

document.getElementById("proceed").onclick = () => {
  chrome.runtime.sendMessage({ type: "allow", url: original }, () => {
    location.href = original;
  });
};
