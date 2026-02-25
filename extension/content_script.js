(function () {
  "use strict";

  // === Списки ключевых слов ===
  const CARD_KEYWORDS = [...];         // оставляем как есть
  const SUSPICIOUS_WORDS = [...];
  const GAMBLING_KEYWORDS = [...];
  const ADULT_KEYWORDS = [...];
  const DRUG_KEYWORDS = [...];

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

  // === Собираем фичи страницы ===
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

  // === Проверка login + captcha ===
  function readyForML() {
    return !hasCaptcha() && !hasPasswordInput();
  }

  // === Анализ страницы через backend ML ===
  async function analyzePageML(features) {
    try {
      const response = await fetch("http://localhost:8000/v1/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: window.location.href,
          features
        }),
      });
      const data = await response.json();

      if (data.block) {
        document.documentElement.innerHTML = `
          <div style="
            display:flex;
            justify-content:center;
            align-items:center;
            height:100vh;
            background:black;
            color:red;
            font-size:24px;
            flex-direction:column;">
            <h1>ACCESS BLOCKED</h1>
            <p>Category: ${data.category}</p>
            <p>Risk score: ${data.risk_score.toFixed(2)}</p>
          </div>
        `;
      }
    } catch (e) {
      console.error("ML scan failed", e);
    }
  }

  // === Главная логика ===
  async function runScan() {
    if (readyForML()) {
      const features = extractFeatures();
      await analyzePageML(features);
    } else {
      // Ждём 2 сек и пробуем снова
      setTimeout(runScan, 2000);
    }
  }

  // === Запускаем после полной загрузки DOM ===
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", runScan);
  } else {
    runScan();
  }
})();
