# VeilAI — Standalone Web MVP

A one-page, browser-based privacy tool based on the supplied VeilAI MVP reference.

## Run locally
Open `index.html` in a modern browser. No build step, package installation, server, API key, or backend is required.

## Included
- Detection for email, phone (Pakistan/international/US patterns), CNIC, IBAN (mod-97 validation), payment cards (Luhn validation), passwords/API tokens/private keys, SSN, IP, DOB, account numbers, and names found through contextual phrases.
- Custom keyword matching and allowlisting.
- Selectable detections, consistent placeholders, local response restoration, copy and TXT download.
- Session counters and responsive layout.

## Important limitations
- This is a client-side MVP, not a complete hosted SaaS. There is no authentication, account system, database, billing, subscription enforcement, team workspace, admin panel, or server API.
- Text is processed in the browser by `app.js`; it is not sent to a VeilAI server. Google Fonts are loaded from Google when internet access is available; the application itself does not require them.
- Detection is heuristic and can miss sensitive content or flag false positives. Always inspect the protected prompt before sending it.
- The session mapping is held in JavaScript memory. Refreshing or closing the tab loses mappings; restoration works only for placeholders created in the current page session.
- The mode selector is a workflow preference; the MVP still uses the explicit Scan and Protect actions. It does not intercept submissions on ChatGPT or other AI websites. Browser extension behavior is separate and not included here.
- This package is not a security certification and anonymization cannot guarantee privacy.

## Deployment
Upload the contents of this folder to any static hosting provider (GitHub Pages, Netlify, Vercel static hosting, etc.). Keep `index.html`, `styles.css`, and `app.js` together in the same directory.
