/**
 * service_worker.js – SafeWeb Parental Control v2
 *
 * Flow:
 * 1. webNavigation.onCommitted fires when user navigates
 * 2. We scan the URL via backend (URL-level features only, fast)
 * 3. SCAM or SUSPICIOUS → redirect to blocked page
 * 4. SAFE → allow, page loads normally
 * 5. content_script runs on loaded page for deeper scan
 */

const DEFAULT_BACKEND_URL = "http://localhost:8000";
const FETCH_TIMEOUT_MS = 5000;
const BLOCK_VERDICTS = ["SCAM", "SUSPICIOUS"];

// Trusted domains — always allowed, never scanned
const TRUSTED_DOMAINS = new Set([
  "google.com", "youtube.com", "wikipedia.org", "github.com",
  "stackoverflow.com", "reddit.com", "twitter.com", "x.com",
  "facebook.com", "instagram.com", "linkedin.com", "apple.com",
  "microsoft.com", "netflix.com", "spotify.com", "telegram.org",
  "whatsapp.com", "discord.com", "twitch.tv", "tiktok.com",
  "pinterest.com", "yahoo.com", "bing.com", "dropbox.com",
  "notion.so", "figma.com", "canva.com", "anthropic.com",
  "openai.com", "cloudflare.com", "zoom.us",
  "khanacademy.org", "coursera.org", "udemy.com", "edx.org",
  "duolingo.com", "quizlet.com", "wolframalpha.com",
]);

const scanningTabs = new Set();

// ── Helpers ───────────────────────────────────────────────────────────────────

function getDomain(url) {
  try { return new URL(url).hostname.replace(/^www\./, ""); }
  catch { return ""; }
}

function isTrusted(url) {
  const d = getDomain(url);
  return [...TRUSTED_DOMAINS].some((t) => d === t || d.endsWith("." + t));
}

function isInternalUrl(url) {
  return ["chrome://", "chrome-extension://", "about:", "devtools://", "edge://"]
    .some((p) => url.startsWith(p));
}

async function getSettings() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(
      { backendUrl: DEFAULT_BACKEND_URL, parentPassword: "" },
      resolve
    );
  });
}

async function fetchWithTimeout(url, options) {
  const ctrl = new AbortController();
  const tid = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try { return await fetch(url, { ...options, signal: ctrl.signal }); }
  finally { clearTimeout(tid); }
}

async function callScan(targetUrl, extraFeatures = {}) {
  const { backendUrl } = await getSettings();
  const domain = getDomain(targetUrl);
  let parsed;
  try { parsed = new URL(targetUrl); } catch { parsed = { pathname: "/" }; }

  const payload = {
    url: targetUrl,
    features: {
      domain_length: domain.length,
      redirect_count: 0,
      has_password_input: false,
      has_card_keywords: false,
      suspicious_words_count: 0,
      gambling_keywords_count: 0,
      subdomain_count: Math.max(0, domain.split(".").length - 2),
      has_punycode: domain.includes("xn--"),
      hyphen_count: (domain.match(/-/g) || []).length,
      path_depth: parsed.pathname.split("/").filter(Boolean).length,
      is_https: targetUrl.startsWith("https"),
      ...extraFeatures,
    },
    meta: {},
  };

  const res = await fetchWithTimeout(`${backendUrl}/v1/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`Backend ${res.status}`);
  return res.json();
}

function buildBlockedUrl(originalUrl, result) {
  const params = new URLSearchParams({
    url: originalUrl,
    verdict: result.verdict,
    score: String(result.risk_score),
    reasons: JSON.stringify(result.reasons || []),
    trace_id: result.trace_id || "",
  });
  return chrome.runtime.getURL(`blocked/index.html`) + "?" + params.toString();
}

function setBadge(tabId, verdict) {
  const map = {
    SAFE:       { text: "✓", color: "#38a169" },
    SUSPICIOUS: { text: "⚠", color: "#dd6b20" },
    SCAM:       { text: "✗", color: "#e53e3e" },
  };
  const b = map[verdict] || { text: "?", color: "#718096" };
  chrome.action.setBadgeText({ text: b.text, tabId });
  chrome.action.setBadgeBackgroundColor({ color: b.color, tabId });
}

// ── Navigation intercept ──────────────────────────────────────────────────────

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const { tabId, url } = details;

  if (isInternalUrl(url)) return;
  if (url.includes(chrome.runtime.id)) return; // already on blocked page
  if (isTrusted(url)) { setBadge(tabId, "SAFE"); return; }
  if (scanningTabs.has(tabId)) return;

  scanningTabs.add(tabId);
  chrome.action.setBadgeText({ text: "…", tabId });
  chrome.action.setBadgeBackgroundColor({ color: "#4299e1", tabId });

  try {
    const result = await callScan(url);
    chrome.storage.session.set({ [`scan_${tabId}`]: { status: "done", result } });

    if (BLOCK_VERDICTS.includes(result.verdict)) {
      chrome.tabs.update(tabId, { url: buildBlockedUrl(url, result) });
      chrome.action.setBadgeText({ text: "🚫", tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#e53e3e", tabId });
    } else {
      setBadge(tabId, result.verdict);
    }
  } catch (err) {
    console.warn("[SafeWeb] scan error:", err.message);
    // Fail open — don't block if backend is unreachable
    chrome.action.setBadgeText({ text: "?", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#718096", tabId });
    chrome.storage.session.set({
      [`scan_${tabId}`]: { status: "error", message: err.message },
    });
  } finally {
    scanningTabs.delete(tabId);
  }
});

// ── Messages from content script & popup ──────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  // Deep scan with page content features (after page loads)
  if (msg.type === "PAGE_FEATURES") {
    const tabId = sender.tab?.id;
    if (!tabId) return false;
    callScan(msg.url, msg.features)
      .then((result) => {
        chrome.storage.session.set({ [`scan_${tabId}`]: { status: "done", result } });
        setBadge(tabId, result.verdict);
        if (result.verdict === "SCAM") {
          chrome.tabs.update(tabId, { url: buildBlockedUrl(msg.url, result) });
        }
      })
      .catch((e) => console.warn("[SafeWeb] deep scan error:", e.message));
    return false;
  }

  // Feedback from popup
  if (msg.type === "SEND_FEEDBACK") {
    getSettings().then(({ backendUrl }) => {
      fetchWithTimeout(`${backendUrl}/v1/feedback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(msg.payload),
      })
        .then((r) => r.json())
        .then((d) => sendResponse({ ok: true, data: d }))
        .catch((e) => sendResponse({ ok: false, error: e.message }));
    });
    return true;
  }

  // Parent password check
  if (msg.type === "CHECK_PASSWORD") {
    getSettings().then(({ parentPassword }) => {
      sendResponse({ ok: msg.password === parentPassword && parentPassword !== "" });
    });
    return true;
  }

  // Allow site temporarily (parent override)
  if (msg.type === "ALLOW_SITE") {
    chrome.storage.session.set({ [`allowed_${msg.hostname}`]: true });
    sendResponse({ ok: true });
    return false;
  }
});
