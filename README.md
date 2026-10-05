**Description:**
A Chrome extension that automatically scans every website you visit, detects scams, gambling, adult content, and dangerous sites using a rule-based scoring engine, and blocks them with a warning page. Logs every scan to a local database.

---

**How to run:**

**Step 1 — Start the backend**
```bash
cd backend
.venv/bin/uvicorn app.main:app --reload
```
Keep this terminal open while using the extension.

**Step 2 — Load the extension in Chrome**
1. Go to `chrome://extensions`
2. Enable **Developer Mode** (top right toggle)
3. Click **Load unpacked**
4. Select the `extension/` folder

**Step 3 — Use it**
- Browse normally — every site gets scanned automatically
- Badge shows: `✓` safe, `⚠` suspicious, `✗` scam
- Dangerous sites get redirected to a blocked page

That's it.
