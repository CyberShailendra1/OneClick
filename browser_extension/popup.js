// OneClick Phishing Guard - popup logic.
// Calls the OneClick REST API's /scan-url endpoint (see api.py) and displays
// the result. This extension only ever DISPLAYS a verdict - it never blocks
// navigation, closes tabs, or modifies page content, matching the same
// flag-only design used throughout the rest of OneClick.

const currentUrlEl = document.getElementById("currentUrl");
const apiBaseEl = document.getElementById("apiBase");
const scanBtn = document.getElementById("scanBtn");
const resultEl = document.getElementById("result");

let activeTabUrl = "";

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  activeTabUrl = tab?.url || "";
  currentUrlEl.textContent = activeTabUrl || "(no active tab URL)";

  const stored = await chrome.storage.local.get("apiBase");
  if (stored.apiBase) apiBaseEl.value = stored.apiBase;
}

scanBtn.addEventListener("click", async () => {
  if (!activeTabUrl || !activeTabUrl.startsWith("http")) {
    resultEl.innerHTML = `<div class="verdict suspicious">Can't scan this page (not an http/https URL).</div>`;
    return;
  }

  const apiBase = apiBaseEl.value.trim().replace(/\/$/, "");
  await chrome.storage.local.set({ apiBase });

  scanBtn.disabled = true;
  scanBtn.textContent = "Scanning...";
  resultEl.innerHTML = "";

  try {
    const resp = await fetch(`${apiBase}/scan-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: activeTabUrl }),
    });
    if (!resp.ok) throw new Error(`API returned ${resp.status}`);
    const data = await resp.json();
    renderResult(data);
  } catch (err) {
    resultEl.innerHTML = `<div class="verdict suspicious">Could not reach OneClick API at ${apiBase}.<br>${err.message}<br><br>Make sure the API is running: <code>uvicorn api:app</code></div>`;
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = "🔍 Check this page";
  }
});

function renderResult(data) {
  const cls = data.label === "Likely Safe" ? "safe" : data.label === "Suspicious" ? "suspicious" : "malicious";
  let html = `<div class="verdict ${cls}">${data.label} — ${data.score}%</div>`;
  if (data.reasons?.length) {
    html += "<ul>" + data.reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("") + "</ul>";
  }
  resultEl.innerHTML = html;
}

function escapeHtml(s) {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

init();
