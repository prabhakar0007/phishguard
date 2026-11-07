/* PhishGuard — background guard (service worker).
   Checks every top-level navigation with the built-in ML model.
   PHISHING  -> redirect the tab to the full-page warning.
   SUSPICIOUS-> yellow "!" badge on the toolbar icon.
   SAFE      -> badge cleared. Everything runs locally; no URL ever
   leaves the browser. */

importScripts("top_domains.js", "model.js", "features.js", "engine.js");

const lastChecked = new Map();   // tabId -> url (avoid repeat work)
const WARNING_PAGE = chrome.runtime.getURL("warning.html");

function isCheckable(url) {
  return url && /^https?:\/\//i.test(url) && !url.startsWith(WARNING_PAGE);
}

async function getAllowed() {
  const data = await chrome.storage.session.get("allowed");
  return new Set(data.allowed || []);
}

async function checkTab(tabId, url) {
  if (!isCheckable(url)) return;
  if (lastChecked.get(tabId) === url) return;
  lastChecked.set(tabId, url);

  const allowed = await getAllowed();
  if (allowed.has(url)) return;   // user explicitly chose to proceed

  let result;
  try {
    result = pgCheck(url);
  } catch (e) {
    return;   // never break browsing on an engine error
  }

  if (result.verdict === "PHISHING") {
    chrome.action.setBadgeText({ tabId, text: "✕" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#dc2626" });
    const target = WARNING_PAGE +
      "?url=" + encodeURIComponent(url) +
      "&risk=" + encodeURIComponent(result.risk_percent);
    chrome.tabs.update(tabId, { url: target });
  } else if (result.verdict === "SUSPICIOUS") {
    chrome.action.setBadgeText({ tabId, text: "!" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#eab308" });
  } else {
    chrome.action.setBadgeText({ tabId, text: "" });
  }
}

chrome.webNavigation.onBeforeNavigate.addListener(details => {
  if (details.frameId === 0) checkTab(details.tabId, details.url);
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.url) checkTab(tabId, changeInfo.url);
});

chrome.tabs.onRemoved.addListener(tabId => lastChecked.delete(tabId));

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.type === "allow") {
    (async () => {
      const allowed = await getAllowed();
      allowed.add(msg.url);
      await chrome.storage.session.set({ allowed: [...allowed] });
      sendResponse({ ok: true });
    })();
    return true;   // async response
  }
  if (msg && msg.type === "check") {
    try {
      sendResponse({ ok: true, result: pgCheck(msg.url) });
    } catch (e) {
      sendResponse({ ok: false, error: String(e) });
    }
  }
});
