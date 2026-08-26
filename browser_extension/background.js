// Minimal background service worker.
// Deliberately does NOT auto-scan every page load or block navigation -
// scanning is always a manual, user-initiated action from the popup,
// consistent with OneClick's "flag, don't auto-act" design principle.

chrome.runtime.onInstalled.addListener(() => {
  console.log("OneClick Phishing Guard installed. Click the toolbar icon to check the current page.");
});
