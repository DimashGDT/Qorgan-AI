(function () {
  "use strict";

  const CARD_KEYWORDS = [
    "credit card", "card number", "cvv", "expiry date", "billing address",
    "payment details", "checkout", "buy now", "card verification",
    "mastercard", "visa card", "debit card", "bank transfer",
  ];

  const SUSPICIOUS_WORDS = [
    "verify your account", "confirm your identity", "update your information",
    "your account has been suspended", "unusual activity", "click here to verify",
    "your password has expired", "login to continue", "secure your account",
    "you have won", "congratulations", "claim your prize", "free gift",
    "urgent action required", "limited time offer", "act now",
    "подтвердите аккаунт", "ваш аккаунт заблокирован",
  ];

  const GAMBLING_KEYWORDS = [
    "place a bet", "live betting", "sports betting", "casino bonus",
    "free spins", "slot machine", "jackpot", "roulette", "blackjack",
    "poker", "odds", "accumulator", "букмекер", "ставки",
    "игровые автоматы", "депозит", "казино", "spin now", "bet now",
  ];

  const ADULT_KEYWORDS = [
    "xxx", "porn", "adult content", "18+", "nude", "erotic",
    "onlyfans", "escort", "webcam girls", "nsfw",
  ];

  const DRUG_KEYWORDS = [
    "buy drugs online", "order cocaine", "buy weed", "marijuana delivery",
    "buy pills online", "dark web", "anonymous delivery", "no prescription needed",
    "amphetamine", "methamphetamine", "mdma", "buy heroin",
  ];

  function getBodyText() {
    try { return (document.body?.innerText || "").toLowerCase().slice(0, 60_000); }
    catch { return ""; }
  }

  function count(text, keywords) {
    return keywords.reduce((acc, kw) => acc + (text.includes(kw) ? 1 : 0), 0);
  }

  function hasPasswordInput() {
    return document.querySelectorAll('input[type="password"]').length > 0;
  }

  function hasCaptcha() {
    return !!document.querySelector("iframe[src*='captcha'], .g-recaptcha");
  }

  function getSubdomainCount(hostname) {
    return Math.max(0, hostname.split(".").length - 2);
  }

  function getRedirectCount() {
    try { return performance.navigation?.redirectCount ?? 0; }
    catch { return 0; }
  }

  function extractFeatures() {
    const hostname = window.location.hostname.toLowerCase();
    const text = getBodyText();
    return {
      domain_length: hostname.length,
      redirect_count: getRedirectCount(),
      has_password_input: hasPasswordInput(),
      has_card_keywords: count(text, CARD_KEYWORDS) > 0,
      suspicious_words_count: count(text, SUSPICIOUS_WORDS),
      gambling_keywords_count: count(text, GAMBLING_KEYWORDS),
      adult_keywords_count: count(text, ADULT_KEYWORDS),
      drug_keywords_count: count(text, DRUG_KEYWORDS),
      subdomain_count: getSubdomainCount(hostname),
      has_punycode: hostname.includes("xn--"),
      hyphen_count: (hostname.match(/-/g) || []).length,
      path_depth: window.location.pathname.split("/").filter(Boolean).length,
      is_https: window.location.protocol === "https:",
      title: document.title,
      meta_description: document.querySelector("meta[name='description']")?.content || "",
      body_snippet: text.slice(0, 2000),
    };
  }

  function readyForScan() {
    return !hasCaptcha() && !hasPasswordInput();
  }

  function sendToServiceWorker(features) {
    try {
      chrome.runtime.sendMessage({
        type: "PAGE_FEATURES",
        url: window.location.href,
        features: features,
      });
    } catch (e) {
      console.warn("[SafeWeb] sendMessage failed", e);
    }
  }

  async function runScan() {
    if (readyForScan()) {
      const features = extractFeatures();
      sendToServiceWorker(features);
    } else {
      setTimeout(runScan, 2000);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", runScan);
  } else {
    runScan();
  }
})();
