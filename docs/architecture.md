# Echo — Project Foundation Architecture

This document explains the files created for the initial milestone (mock UI + mock API).

Frontend (React + Vite)
- `frontend/package.json`: Vite and React scripts and deps.
- `frontend/index.html`: App mount point.
- `frontend/src/main.jsx`: React entry file.
- `frontend/src/App.jsx`: Root component switching between landing and dashboard.
- `frontend/src/components/Landing.jsx`: Landing page with inputs and "Generate Visibility Report" button.
- `frontend/src/components/Dashboard.jsx`: Mock dashboard with cards and views.
- `frontend/src/styles.css`: Centralized styles: deep navy, subtle stars, gradients, card styles.

Backend (FastAPI)
- `backend/app/main.py`: FastAPI app exposing mock endpoints:
  - `POST /report` — returns a mocked report JSON for the provided username/email/website.
  - `GET /score` — returns a mocked visibility score.
  - `GET /recommendations` — returns generic mocked recommendations.
- `backend/requirements.txt`: Python dependencies to install (`fastapi`, `uvicorn`).

Design notes
- The UI uses a deep navy background, subtle star patterns, and elegant gradients for a professional, space-inspired aesthetic.
- All data is mocked; no real internet lookups, scraping, AI, or databases are implemented.

Next steps
- Add API versioning and clear schemas under `backend/app/schemas.py`.
- Add tests and CI pipeline for linting and type checks.
- Replace mock responses with real analysis modules once allowed.
