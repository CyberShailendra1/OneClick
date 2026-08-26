# OneClick Phishing Guard — Browser Extension

A minimal Chrome/Edge (Manifest V3) extension that lets you check the current
page's URL against OneClick's phishing scanner with one click.

## Design principle (same as the rest of OneClick)

**Flag-only.** This extension never blocks navigation, closes tabs, injects
warnings into pages, or does anything automatically. It only shows you a
verdict when you click the toolbar icon and press "Check this page" — you
decide what to do with that information.

## Setup

1. Start the OneClick API (from the project root):
   ```bash
   uvicorn api:app --host 0.0.0.0 --port 8000
   ```
2. In Chrome/Edge, go to `chrome://extensions` (or `edge://extensions`).
3. Enable **Developer mode** (top right).
4. Click **Load unpacked** and select this `browser_extension/` folder.
5. Click the OneClick icon in your toolbar, confirm the API base URL
   (default `http://localhost:8000`), and click **Check this page**.

## Status / testing note

This was tested end-to-end in a real Chromium browser (loaded via the same
`--load-extension` mechanism as `chrome://extensions` → "Load unpacked"):
the service worker registered correctly, the popup loaded, and clicking
"Check this page" successfully called the OneClick API (`POST /scan-url`)
over CORS and rendered a live phishing verdict with reasons. The one part
that couldn't be exercised through browser automation is the exact
"currently active tab" detection you get from physically clicking the
toolbar icon in normal use (a Playwright/automation limitation, not an
extension bug) — that part is straightforward standard `chrome.tabs` API
usage, but do a quick manual click-through after loading it yourself to
confirm it feels right in daily use.

## Files

- `manifest.json` — Manifest V3 config
- `popup.html` / `popup.js` — the toolbar popup UI and its logic (calls `POST /scan-url`)
- `background.js` — minimal service worker (intentionally does nothing automatic)
- `icon16.png` / `icon48.png` / `icon128.png` — placeholder icons (swap for your own branding)
