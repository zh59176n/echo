# Echo

Privacy scanner — enter a username/email and see what's publicly findable across developer platforms, social media, and DNS records.

**[Live Demo →](https://echo-psi-six.vercel.app)**

![Echo Dashboard](screenshots/dashboard.png)

<details>
<summary>More screenshots</summary>

![Landing page](screenshots/landing.png)
![Threat Actor view with MITRE ATT&CK mapping](screenshots/threat-view.png)

</details>

---

## What it does

Scans GitHub, GitLab, DEV.to, HackerNews, Keybase, Mastodon, and Gravatar concurrently, then does DNS + WHOIS on any linked domain. Generates a visibility score and surfaces exposure risks — then shows the same data from three different angles:

- **Recruiter** — professional presence, activity signals
- **Advertiser** — what can be inferred about you from public data
- **Threat Actor** — realistic attack vectors mapped to [MITRE ATT&CK](https://attack.mitre.org/tactics/TA0043/) techniques

Two modes: **Quick Scan** (GitHub + Keybase + Gravatar, ~5s) and **Deep Scan** (everything + DNS/WHOIS, ~15s).

---

## Stack

**Frontend** — React 18, Vite 5, vanilla CSS

**Backend** — FastAPI + `httpx` for async requests, `dnspython` for DNS lookups, `python-whois` in a thread executor so it doesn't block the event loop

All platform checks run concurrently via `asyncio.gather`.

---

## Running locally

```bash
# backend
cd backend && .venv/bin/uvicorn app.main:app --reload

# frontend
cd frontend && npm install && npm run dev
```

Vite proxies `/api/*` to `localhost:8000`.

---

## Deploy

Backend → [Render](https://render.com) (configured via `render.yaml`)  
Frontend → [Vercel](https://vercel.com) (set root directory to `frontend/`)

Update the Render URL in `frontend/vercel.json` before deploying Vercel.

---

Zara Hameedi — B.S. Computer Science, Pace University
