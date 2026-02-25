/**
 * content_script.js – SafeWeb v2
 * Runs at document_start for early interception signal,
 * then document_idle for deep content scanning.
 */
(function () {
  "use strict";

  const CARD_KEYWORDS = [
    "credit card", "card number", "cvv", "expiry date",
    "billing address", "checkout", "payment", "buy now",
  ];

  const SUSPICIOUS_WORDS = [
    "verify", "confirm", "update", "login", "secure", "suspended",
    "unusual activity", "urgent", "limited time", "free prize",
    "winner", "congratulations", "wire transfer", "bitcoin",
  ];

  const GAMBLING_KEYWORDS = [
    "place a bet", "live betting", "sports betting", "casino bonus",
    "free spins", "slot machine", "jackpot", "roulette", "blackjack",
    "poker", "odds", "accumulator", "sportsbook", "bookmaker",
    "deposit bonus", "welcome bonus", "wagering", "cashout",
    "ставки на спорт", "игровые автоматы", "букмекер",
    "бесплатные вращения", "казино", "слоты", "джекпот",
  ];

  const ADULT_KEYWORDS = [
    "porn", "xxx", "nude", "naked", "adult content", "18+",
    "onlyfans", "escort", "cam girls", "sex chat",
  ];

  const DRUG_KEYWORDS = [
    "buy drugs", "order cocaine", "buy weed online", "darknet market",
    "buy pills", "mdma", "fentanyl", "methamphetamine", "buy firearms",
  ];

  function getBodyText() {
    try {
      return (document.body?.innerText || "").toLowerCase().slice(0, 60_000);
    } catch { return ""; }
  }

  function count(text, keywords) {
    return keywords.reduce((acc, kw) => acc + (text.includes(kw) ? 1 : 0), 0);
  }

  function hasPasswordInput() {
    return document.querySelectorAll('input[type="password"]').length > 0;
  }

  function getSubdomainCount(hostname) {
    return Math.max(0, hostname.split(".").length - 2);
  }

  function getRedirectCount() {
    try { return performance.navigation?.redirectCount ?? 0; }
    catch { return 0; }
  }

  // Wait for page to be ready then do deep scan
  function deepScan() {
    const hostname = window.location.hostname.toLowerCase();
    const text = getBodyText();

    const features = {
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
    };

    chrome.runtime.sendMessage({
      type: "PAGE_FEATURES",
      url: window.location.href,
      features,
    });
  }

  // Run deep scan after DOM is ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", deepScan);
  } else {
    deepScan();
  }
})();
