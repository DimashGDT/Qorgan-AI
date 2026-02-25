# Scam Detector – Chrome Extension (Manifest V3)

## Structure

```
extension/
  manifest.json        # MV3 manifest
  service_worker.js    # Background: calls backend API, stores results
  content_script.js    # Injected: extracts page features, sends to SW
  popup.html           # Badge popup UI
  popup.js             # Popup logic: reads results, sends feedback
  styles.css           # Popup styles
  icons/               # Place icon16.png, icon48.png, icon128.png here
  README.md
```

## Prerequisites

- Google Chrome 114+
- Backend running on `http://localhost:8000` (see backend/README.md)

## Loading the extension in Chrome

1. Open `chrome://extensions`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the `extension/` folder

The extension loads and appears in the toolbar. Copy the **Extension ID** shown
on the extensions page (e.g. `abcdefghijklmnopqrstuvwxyz123456`) – you will need
it to configure CORS on the backend.

## Configuring backend URL

The default backend URL is `http://localhost:8000`. To change it:

1. Click the 🛡️ icon in the toolbar to open the popup
2. Click **⚙ Settings** at the bottom
3. Enter your backend URL and click **Save**

Or set it programmatically by running in the browser console:
```javascript
chrome.storage.sync.set({ backendUrl: "http://my-server:8000" });
```

## How it works

1. When a page loads, `content_script.js` collects these features:
   - `domain_length`, `redirect_count` (best-effort via `performance.navigation`)
   - `has_password_input` — true if any `<input type="password">` is present
   - `has_card_keywords` — true if payment/card text is detected in visible text
   - `suspicious_words_count` — count of phishing-related words in visible text
   - `subdomain_count`, `has_punycode`, `hyphen_count`, `path_depth`, `is_https`

2. Features are sent to `service_worker.js`, which POSTs them to `/v1/scan`.

3. The result (verdict + score + reasons) is stored in `chrome.storage.session`.

4. When you open the popup, it reads the stored result and renders it.

5. You can report false positives/negatives with the feedback buttons.

## Limitations & best-effort notes

### redirect_count
`performance.navigation.redirectCount` only counts redirects within the same
origin chain visible to the browser. Cross-origin redirects reset the counter.
This is a browser limitation and cannot be fully worked around in MV3 content
scripts. The value is still useful as a signal, just not perfectly accurate.

### Icons
The `icons/` directory must contain `icon16.png`, `icon48.png`, `icon128.png`.
You can create simple placeholder PNGs or use any 16×16, 48×48, 128×128 images.
The extension will load without them but the toolbar icon will be blank.

## Testing locally

1. Start the backend:
   ```bash
   cd backend && uvicorn app.main:app --reload
   ```

2. Load the extension (see above).

3. Set CORS on the backend:
   ```bash
   export ALLOWED_ORIGINS="chrome-extension://YOUR_EXTENSION_ID"
   ```

4. Navigate to any suspicious URL, then click the toolbar icon.

## Privacy notice

- No full URLs, raw HTML, or personal data are ever sent to the backend.
- Only aggregated feature flags/counts are transmitted.
- The backend stores only a SHA-256 hash of the URL, never the URL itself.
- All data remains on your local machine (SQLite database in the backend folder).
