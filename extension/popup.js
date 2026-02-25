"use strict";
const $ = (id) => document.getElementById(id);

function showState(name) {
  ["loading","error","result","idle"].forEach((s) =>
    $(`state-${s}`).classList.add("hidden")
  );
  $(`state-${name}`).classList.remove("hidden");
}

function verdictClass(v) {
  return { SAFE:"safe", SUSPICIOUS:"suspicious", SCAM:"scam" }[v] || "safe";
}

function verdictSub(v) {
  return {
    SAFE: "No threats detected ✓",
    SUSPICIOUS: "Proceed with caution ⚠",
    SCAM: "Dangerous site blocked 🚫",
  }[v] || "";
}

const popup = { _traceId: null };

function renderResult(result) {
  $("score-value").textContent = result.risk_score;
  $("verdict-label").textContent = result.verdict;
  $("verdict-sub").textContent = verdictSub(result.verdict);

  const banner = $("verdict-banner");
  banner.className = `verdict-banner ${verdictClass(result.verdict)}`;

  const ul = $("reasons-list");
  ul.innerHTML = "";
  (result.reasons || []).forEach((r) => {
    const li = document.createElement("li");
    li.textContent = r;
    ul.appendChild(li);
  });

  popup._traceId = result.trace_id;
  showState("result");
}

// Feedback
function sendFeedback(label) {
  if (!popup._traceId) return;
  $("btn-safe").disabled = true;
  $("btn-scam").disabled = true;
  chrome.runtime.sendMessage(
    { type:"SEND_FEEDBACK", payload:{ trace_id: popup._traceId, user_label: label } },
    (res) => {
      const s = $("feedback-status");
      s.textContent = res?.ok ? "✔ Feedback sent!" : "⚠ Could not send.";
      s.style.color  = res?.ok ? "#38a169" : "#e53e3e";
      s.classList.remove("hidden");
    }
  );
}
$("btn-safe").addEventListener("click", () => sendFeedback("SAFE"));
$("btn-scam").addEventListener("click", () => sendFeedback("SCAM"));

// Settings panel
$("settings-link").addEventListener("click", (e) => {
  e.preventDefault();
  const panel = $("settings-panel");
  panel.classList.toggle("hidden");
  if (!panel.classList.contains("hidden")) {
    chrome.storage.sync.get(["backendUrl","parentPassword"], (res) => {
      $("backend-url-input").value   = res.backendUrl      || "http://localhost:8000";
      $("parent-password-input").value = res.parentPassword || "";
    });
  }
});

$("save-settings").addEventListener("click", () => {
  const url = $("backend-url-input").value.trim().replace(/\/$/, "");
  const pw  = $("parent-password-input").value;
  chrome.storage.sync.set({ backendUrl: url, parentPassword: pw }, () => {
    const s = $("settings-status");
    s.classList.remove("hidden");
    setTimeout(() => s.classList.add("hidden"), 2000);
  });
});

// Load result for current tab
chrome.tabs.query({ active:true, currentWindow:true }, ([tab]) => {
  if (!tab?.id) { showState("idle"); return; }

  const key = `scan_${tab.id}`;
  chrome.storage.session.get([key], (data) => {
    const entry = data[key];
    if (!entry)                  { showState("idle"); return; }
    if (entry.status === "done") { renderResult(entry.result); return; }
    if (entry.status === "error"){ $("error-text").textContent = entry.message || "Unknown error"; showState("error"); return; }

    showState("loading");
    const poll = setInterval(() => {
      chrome.storage.session.get([key], (d) => {
        const e = d[key];
        if (!e || e.status === "scanning") return;
        clearInterval(poll);
        if (e.status === "done") renderResult(e.result);
        else { $("error-text").textContent = e.message || "Error"; showState("error"); }
      });
    }, 400);
  });
});
