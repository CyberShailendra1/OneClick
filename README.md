
# 🛡️ OneClick APK Analyzer

Multi-layer Android malware detector — known threats (VirusTotal signatures), unknown/zero-day threats (static + AI analysis), and optional runtime behavior analysis.

## Architecture

| Layer | What it does | Tech |
|---|---|---|
| 1 | SHA-256 hash → VirusTotal lookup (cached locally) | `requests` + VirusTotal v3 API + SQLite |
| 2 | Decompile APK, extract permissions, suspicious API calls, cert/metadata | `androguard` |
| 2b | Strings/URL/IP extraction, obfuscation (entropy) detection, native `.so` inventory, exported-component check, third-party SDK fingerprinting | custom (`modules/advanced_static.py`) |
| 3 | Risk score 0–100% + rule-based **and** SHAP feature-attribution explanations | `scikit-learn` (RandomForest) / `xgboost` + `shap` |
| 4 | Traffic-light dashboard, batch scanning, scan history, PDF/JSON report export | `streamlit`, `reportlab`, SQLite |
| 5 | *(optional)* Runtime behavior observation — SMS sends, dynamic code loading, network calls | ADB + Frida (needs Android SDK/emulator on your machine) |
| 6 | Phishing/malicious-URL scanner — heuristics + VirusTotal URL reputation + optional safe landing-page investigation | `modules/phishing_scanner.py`, `beautifulsoup4` |

There's also a **FastAPI backend** (`api.py`) exposing the same pipeline as REST endpoints, and a **batch CLI** (`batch_scan.py`) for scanning a whole folder from the terminal — useful for CI pipelines or bulk triage.

## Phishing & Malicious URL Scanner (Layer 6)

A separate tab from APK scanning — paste a single URL, or an entire SMS/email/WhatsApp message (links are auto-extracted), and OneClick flags it as **Likely Safe / Suspicious / Phishing-Malicious**.

**Design principle: flag, never auto-act.** Every result is a recommendation for *you* to review — OneClick never deletes, blocks, or modifies anything automatically. This was a deliberate choice: automatic deletion on a false positive would silently destroy a legitimate message (an OTP, a bank notice) with no way to undo it. Instead:
- Risky links get a warning and three buttons: **"I deleted this myself"**, **"Dismiss (false positive)"**, and **"Report to authorities info"** (points to cybercrime.gov.in / 1930 for India) — all of which just *log what you decided*, none of which take action on your behalf.
- Every scan and every decision is saved to a **URL History** tab you can review or clear at any time.

**Detection layers:**
1. **Heuristics** (instant, offline) — IP-based hosts, `@` tricks, URL shorteners, missing HTTPS, suspicious TLDs (`.tk`, `.top`, etc.), excessive subdomains, urgency keywords ("verify", "suspended"), punycode/homograph domains, and typosquat detection against a short list of commonly-impersonated brands (catches things like `paypa1-secure.tk`).
2. **VirusTotal URL reputation** (optional, reuses the same API key as APK scanning) — checks the URL against dozens of aggregated blocklists.
3. **🔬 Investigate (opt-in, per-link)** — safely follows the redirect chain and fetches the final landing page to answer *"where does this actually lead, and what will it do?"*:
   - Shows the full redirect chain and final destination.
   - Parses forms to detect **credential-harvesting patterns** (password/OTP/card fields submitting to a different domain than the page itself).
   - Flags `<meta refresh>` auto-redirect tricks.
   - Flags obfuscated inline scripts (`eval`, `atob`, `document.write`, etc.) via static pattern matching.
   - Lists external script domains the page loads.

   This is **strictly read-only**: it never executes JavaScript, submits forms, or downloads files — it parses raw HTML the way a search-engine crawler would. It's also **SSRF-guarded**: every redirect hop's resolved IP is checked and rejected if it's private/loopback/internal, so a malicious redirect can't be used to probe your own network. Because it means actually contacting the destination server, it's a separate opt-in action per link rather than something that runs automatically on every scan.

## OTP / Code Auto-Redaction (Layer 7)

A dedicated **🔒 OTP Guard** tab (and automatically applied to the phishing scanner's "paste a message" flow): paste an SMS/email/WhatsApp message, and any OTP or verification code in it is **automatically hidden** before it's displayed, stored, or exported.

**Scope note:** OneClick is a web tool, not a native phone app — it can't read your live SMS/email inbox and intercept OTPs the moment they arrive. This works on text you paste in yourself (e.g. before pasting a message into a support chat, or checking a link in it for phishing here). Real-time interception on-device would need a native Android app with notification access — a possible future extension, not part of this web tool.

**How detection works:**
- **Keyword-anchored**: a bare 4-8 digit number is only masked if it appears near an OTP-related phrase (*"OTP"*, *"verification code"*, *"PIN is"*, *"code hai"*, *"OTP hai"* for common Hinglish phrasing, etc.) — this avoids masking phone numbers, order IDs, or amounts that just happen to be nearby.
- Covers both numeric codes (`483920`, `123-456`) and short alphanumeric codes (`A3B9F2`).
- The real code value is **never returned by the detection function itself** — only a redacted string and a count — so it can't leak even through history or logs.

## Setup (native, on Kali or any Linux)

```bash
cd OneClick
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt

# Train the Layer-3 model (creates models/rf_model.joblib)
python models/train_model.py

# Launch the server (serves both REST API and React Web UI)
uvicorn api:app --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000` in your browser. Configure your **free VirusTotal API key** via the `.env` file or directly in the UI.

### If the server fails to start

Run the doctor script first — it checks every dependency individually and reports exactly what is missing:

```bash
python3 doctor.py
```

Then use the robust launcher, which auto-restarts on crash and logs to `logs/`:

```bash
./start.sh                # foreground, auto-restart on crash, logs to logs/
./start.sh --no-restart   # foreground, exit immediately on crash (best for debugging)
./start.sh --port 8000    # custom port
```

For a real deployment (survives SSH disconnects, restarts on reboot), use the included systemd service instead of a bash loop:

```bash
# Edit the User/WorkingDirectory paths in oneclick.service first, then:
sudo cp oneclick.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now oneclick

sudo systemctl status oneclick     # is it running?
sudo journalctl -u oneclick -f     # live logs
```

**Known real fix already applied:** earlier versions of this app imported `pyzbar` (QR scanner) and `pytesseract` (OCR scanner) at the top of `app.py`. If their system dependencies (`libzbar0`, `tesseract-ocr`) weren't installed, importing `app.py` raised an `ImportError` immediately — which is exactly the "starts then closes" symptom. This is now fixed: those imports are wrapped so a missing system dependency only disables that one tab (with a clear fix message in the UI and sidebar) instead of crashing the whole app. Run `python3 doctor.py` to check for exactly this.

### React + TypeScript Web UI & FastAPI Backend

A modern, fast web dashboard built with **React, TypeScript, and Vite** that connects to the FastAPI backend with all primary security analysis features:

```bash
# Start the FastAPI backend (serves both API and the built React UI at http://localhost:8000):
uvicorn api:app --host 0.0.0.0 --port 8000

# Optional: To run the frontend in Vite live development mode:
cd frontend
npm run dev    # opens on http://localhost:3000 with API proxy to port 8000
```

Interactive API docs are available at `http://localhost:8000/docs`.
Endpoints: `POST /scan`, `POST /scan/report` (PDF/JSON), `GET /history`, `POST /scan-url`, `POST /investigate-url`, `POST /scan-message`, `POST /redact-message`, `POST /scam-lookup/phone`, `POST /scam-lookup/upi`, `POST /breach/password`.

### Batch CLI

```bash
python batch_scan.py /path/to/apks/ --vt-key YOUR_KEY --out results.json
python batch_scan.py /path/to/apks/ --no-advanced   # faster, skips Layer 2b
```

### Docker

```bash
docker compose up --build
# UI:  http://localhost:8501
# API: http://localhost:8000/docs
```

Note: the Docker image excludes `frida`/`frida-tools` since a container has no Android emulator attached — dynamic analysis (Layer 5) only works when run natively on a machine with Android SDK tooling.

## Layer 5 — Dynamic Analysis (needs setup on your Kali machine)

**This was the one layer I could not test end-to-end**, because the sandbox this project was built in has no Android SDK, no emulator, and no physical device. The code in `modules/dynamic_analysis.py` follows the standard ADB + Frida workflow and I verified its environment-check/fallback logic works correctly, but **you should validate the actual install → hook → observe flow on your Kali box** before relying on its output.

Setup:
```bash
sudo apt install android-tools-adb android-tools-fastboot
pip install frida-tools frida
# then start an Android emulator (AVD via Android Studio, or Genymotion / Android-x86),
# OR connect a rooted physical device
```

Once a device/emulator is detected, the "🏃 Dynamic Analysis" tab in the dashboard will let you run it. It installs the APK, launches it, hooks SMS-send / dynamic-class-loading / `Runtime.exec` / file-write APIs via Frida, observes for N seconds, then uninstalls the app. Always run this against a disposable/snapshotted emulator — never your primary device — since the APK under test could be real malware.

## ⚠️ Honesty note on accuracy

No malware classifier — commercial antivirus included — hits 100% accuracy; malware evolves faster than any static rule set or model. What's actually solid here:

- **Layer 1 (VirusTotal)** is as reliable as VirusTotal's own multi-engine consensus for *known* malware.
- **Layer 3 (Random Forest / XGBoost)** ships trained on a **SYNTHETIC dataset** (`models/train_model.py` generates it from documented malware behavior patterns) since no real labeled dataset was provided. It works end-to-end out of the box, but for production accuracy retrain on a real dataset:

```bash
python models/train_model.py --csv your_real_dataset.csv --model xgboost
```
  The CSV needs all columns in `FEATURE_NAMES` (see `modules/ml_classifier.py`) plus a `label` column (1=malicious, 0=benign). Good sources: [CICMalDroid 2020](https://www.unb.ca/cic/datasets/maldroid-2020.html), [Drebin](https://www.sec.cs.tu-bs.de/~danarp/drebin/), or AndroZoo APKs labeled via VirusTotal.
- **Layer 5 (dynamic analysis)** is untested in this build environment — verify on your machine.

## Additional Protections (Layers 8-11)

Beyond the core APK/URL/OTP pipeline, OneClick includes several more targeted safety tools — all following the same **flag-only, never auto-act** philosophy:

| Feature | Tab | What it does | Testing status |
|---|---|---|---|
| **QR ("quishing") scanner** | 📷 QR Scanner | Decodes a QR image; runs any URL through the phishing pipeline, and checks UPI payment QRs against the scam-VPA list | ✅ Fully tested (phishing/safe/UPI cases) |
| **Screenshot scam scanner** | 📋 Screenshot Scanner | OCR's a pasted screenshot, then runs it through URL scanning + OTP redaction + scam-pattern detection in one pass | ✅ Fully tested end-to-end |
| **Fake banking-app detector** | (in Single Scan) | Flags APKs impersonating known banking/UPI apps (typosquat package names, or a brand name with an unrelated real package) | ✅ Fully tested, false-positive-checked |
| **Scam script pattern detector** | (used by Screenshot Scanner) | Matches text against common scam templates: digital arrest, fake courier, lottery, fake job, tech support, fake KYC, loan scams, romance scams | ✅ Fully tested |
| **Scam number / UPI lookup** | 📞 Scam Lookup | Checks a phone number or UPI ID against a local, extensible reported-scam list; lets you add your own reports | ✅ Fully tested (this is a **local list bundled with the install**, not a live crowdsourced service) |
| **Domain age (WHOIS) check** | 📞 Scam Lookup (bottom) | Flags newly-registered domains — a strong independent phishing signal | ⚠️ Code correct, but WHOIS (port 43) was unreachable from the sandbox this was built in — verify on your own network |
| **Breach checker** | 🕵️ Breach Checker | Password check via HIBP's free k-anonymity API (password never transmitted); email check via HIBP's paid API (bring your own key) | ⚠️ Written to HIBP's documented API contract but untestable here (network-restricted sandbox, no paid key available) |
| **Browser extension** | `browser_extension/` | One-click "check this page" popup that calls the OneClick API | ✅ Tested end-to-end in a real Chromium instance (loaded, called the API over CORS, rendered a live verdict) |
| **Telegram bot** | `telegram_bot.py` | Forward a link, message, screenshot, or QR code straight to a Telegram bot; get an instant flag-only verdict via `/scan`, `/checknumber`, `/checkupi`, or just by sending text/photos | ✅ Core logic fully unit tested (11/11 tests, `tests/test_telegram_bot.py`), including mocked handler-wiring tests. Live polling against Telegram's servers untestable here (no network path to api.telegram.org in this sandbox) — get a token from @BotFather and test on your own machine. |

### Telegram bot setup

```bash
# 1. Message @BotFather on Telegram, run /newbot, copy the token it gives you
export ONECLICK_TELEGRAM_TOKEN="your-token-here"
export ONECLICK_VT_API_KEY="your-virustotal-key"   # optional

# 2. Run it
python3 telegram_bot.py
```

Then message your bot on Telegram: send it a link, forward it a suspicious SMS/WhatsApp text, or send a photo/QR code. Try `/scan <url>`, `/checknumber <number>`, or `/checkupi <upi_id>` for targeted checks. Run the test suite any time with `python3 -m pytest tests/test_telegram_bot.py -v`.




```
OneClick/
├── api.py                     # FastAPI backend (serves REST endpoints and React Web UI)
├── batch_scan.py              # CLI batch scanner
├── requirements.txt           # Python dependencies
├── Dockerfile / docker-compose.yml
├── .env / .env.example        # Environment variables & API keys
├── frontend/                  # React + TypeScript Web Dashboard
│   ├── src/                   # Components (SingleScan, BatchScan, History, Phishing, OTP, Scam)
│   ├── dist/                  # Production static assets served by FastAPI
│   └── package.json
├── modules/
│   ├── pipeline.py            # Shared scan pipeline used by api.py and batch_scan.py
│   ├── hash_scanner.py        # Layer 1: SHA-256 + VirusTotal
│   ├── static_analyzer.py     # Layer 2: Androguard extraction
│   ├── advanced_static.py     # Layer 2b: IOCs, obfuscation, native libs, SDKs, exported components
│   ├── ml_classifier.py       # Layer 3: featurization + RF/XGBoost scoring + rule-based explainability
│   ├── shap_explainer.py      # Layer 3: SHAP-based per-prediction feature attribution
│   ├── dynamic_analysis.py    # Layer 5: ADB + Frida runtime hooks (needs Android SDK)
│   ├── database.py            # SQLite: scan history + VirusTotal result cache
│   └── report_generator.py    # PDF/JSON report export
├── models/
│   ├── train_model.py         # Trains RF or XGBoost, --csv flag for real datasets
│   └── rf_model.joblib        # (generated after training)
└── sample_data/
    └── training_data.csv      # synthetic training set
```

## Notes

- All static analysis is 100% passive — the APK is decompiled/inspected, never executed, so Layers 1–3 are safe to run on your own machine even against a real malware sample.
- Extend `DANGEROUS_PERMISSIONS` / `SUSPICIOUS_APIS` in `modules/static_analyzer.py`, and `KNOWN_SDKS` in `modules/advanced_static.py`, as you learn about new patterns.
- VirusTotal free tier is rate-limited (4 requests/min) — the local SQLite cache (24h TTL) helps avoid re-querying the same hash.
- Scan history and the VT cache live in `oneclick.db` (SQLite) at the project root, created automatically on first scan.
