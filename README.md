# CyberGuard AI — AI-Enhanced Cybersecurity Threat Detector

[![CI](https://github.com/teevexa/cyberguard-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/teevexa/cyberguard-ai/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

An open-source project by [Teevexa Ltd](https://www.teevexa.com).

A lightweight threat-detection dashboard for teams too small for an enterprise SIEM: ingest network traffic, score it for anomalies with a real trained ML model, get alerted over Slack/email/webhook, and get plain-language triage help from a locally-run AI assistant — no third-party API spend required.

Built incrementally in the open, started as a solo project and now maintained by Teevexa. This README always reflects what's actually implemented, not what's planned — see [Roadmap](#roadmap) for what's not built yet, and [CONTRIBUTING.md](CONTRIBUTING.md) if you'd like to help build it.

---

## Status

| Layer | Status | Notes |
|---|---|---|
| Frontend (React dashboard) | 🟢 Live for 8/8 pages | No page shows demo/mock data anymore |
| Backend API | 🟢 Live | FastAPI, connected to Neon Postgres |
| Database | 🟢 Live | Neon (serverless Postgres) |
| Authentication | 🟢 Live | Neon Auth (Better Auth), JWT verified via JWKS, RBAC via `neon_auth.user.role` |
| Anomaly detection | 🟢 Live | RandomForestClassifier on real UNSW-NB15 data, 82% accuracy — retrainable from the UI |
| Explainability | 🟢 Live | Real `feature_importances_` chart on Models, per-threat z-score "Why Flagged" breakdown on Threats |
| Log-source ingestion | 🟢 Live | Real UDP syslog receiver (RFC 3164-ish), parses/flags/persists actual syslog packets — see below |
| Alert delivery | 🟢 Live | Slack Incoming Webhook, Gmail SMTP, generic HMAC-signed webhook — all fire automatically on detection |
| Incident management | 🟢 Live | Real CRUD, linked to threats, notes, status workflow |
| User management | 🟢 Live | Real roles, real account suspension (enforced, not decorative) |
| Tests / CI | 🟢 Live | 127 backend (pytest) + 15 frontend (Vitest) tests, GitHub Actions on every push/PR |
| AI triage assistant | 🟢 Live | "Triage with AI" on any threat — local Llama 3.1 8B via Ollama, cached per threat, no paid API |
| Security hardening | 🟢 Live | Real per-org API keys, secrets masked for non-Admins, rate limiting, persisted audit log — see below |
| Multi-tenancy | 🟢 Live | Real Neon Auth `organization` plugin — every table org-scoped, verified server-side, not client-trusted |
| Public API | 🟢 Live | Per-organization ingest keys (hashed at rest, one-time reveal), self-documenting via FastAPI's real OpenAPI at `/docs` |
| Compliance evidence export | 🟢 Live | Real ZIP of incidents/threats/audit log for a date range — CSVs, not a fabricated badge |
| SSO | 🟡 Google only | Real "Continue with Google" OAuth login — see [SSO](#sso) for what this is and isn't |

🟢 working · 🟡 partial · ⚪ not started

**Log-source ingestion, honestly scoped:** the ML anomaly detector runs on UNSW-NB15 network *flow* data — it was never going to make sense to also claim it "detects threats" in free-text syslog lines, since that's a different data shape the model was never trained on. So `Logs` doesn't reuse the RandomForest model at all. Instead, `backend/syslog_server.py` is a real asyncio UDP listener (started via FastAPI's lifespan hook, default port 1514) that parses actual RFC 3164-ish syslog packets and flags them with simple, honest severity/keyword rules — a genuinely different, correctly-scoped detection approach for a genuinely different kind of data. Plain UDP has no header to carry org identity, so a sender can optionally prepend a real per-org API key as a `[key:...]` token at the start of the message text (stripped before storage) to get routed to that org; no token, an unknown key, or a revoked one all fall back to a bootstrap "default" organization rather than dropping the message.

**Multi-tenancy, built on the real thing:** rather than hand-rolling organizations/members/invitations, this uses Neon Auth's actual Better Auth `organization` plugin — confirmed live (not assumed from docs) that `neon_auth.organization`/`member`/`invitation` tables were already provisioned on this Neon Auth instance. Every domain table (`log_events`, `threats`, `incidents`, `notification_settings`, `app_settings`, `system_logs`) carries an `organization_id`; every endpoint resolves the caller's org from a real `X-Organization-Id` header, verified server-side against `neon_auth.member` — never trusted from the client. Org creation/switching and member invite/role/remove all call Neon Auth's real client methods directly (`backend/auth.py`'s `require_org_member`/`require_org_role`, `src/lib/OrgContext.tsx`).

---

## Architecture

```
┌─────────────────────────┐
│  Frontend (React/Vite)  │  dashboard, charts, alert triage UI, auth
└────────────┬─────────────┘
             │ HTTPS + Bearer JWT
┌────────────▼─────────────┐
│   Backend (FastAPI)      │  JWT verification, CRUD, detection, alert dispatch
└──┬──────────┬──────────┬─┘
   │          │          │
┌──▼───┐ ┌────▼────┐ ┌───▼──────────────┐
│ Neon │ │ Neon    │ │ Slack / SMTP /   │
│ PG   │ │ Auth    │ │ webhook / Ollama │
└──────┘ └─────────┘ └──────────────────┘
```

Deliberately **one backend service**, not a service-per-concern split: FastAPI owns the database, auth verification, the detection logic, and alert dispatch. Anomaly scoring uses classical, self-hosted ML (not an LLM call) because it needs to be cheap and fast on every ingested log line. Authentication is Neon Auth (Better Auth under the hood) — the frontend talks to it directly for sign-in/sign-up, and the backend verifies the resulting JWT statelessly via Neon's public JWKS endpoint (no shared secret, no Node runtime required on the Python side). The AI assistant is reserved for the low-volume, human-reviewed task of explaining an alert and suggesting next steps — runs locally via [Ollama](https://ollama.com) rather than a paid API, by design. The syslog UDP listener runs inside the same asyncio event loop as uvicorn (via a `lifespan` context manager) rather than as a separate process — one less thing to deploy and monitor for a small, single-service deployment.

See [`backend/`](backend/) for the API and [`src/`](src/) for the frontend.

---

## Local setup

### Frontend
```bash
npm install
cp .env.example .env.local   # fill in VITE_NEON_AUTH_URL from your own Neon project
npm run dev                  # http://localhost:8080
```

### Backend
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in DATABASE_URL, NEON_AUTH_URL, INGEST_API_KEY, and (optionally) SMTP_* for email alerts
python init_db.py      # creates all tables on your Neon database
uvicorn main:app --reload --port 8000   # http://localhost:8000/health
```

`INGEST_API_KEY` is an optional **legacy** shared key for `POST /events/ingest`, kept for backward compatibility and always attributed to the default org — generate one with:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```
The real, current way to authenticate ingestion is a **per-organization key**: Settings → Organization → API Keys → Create Key, once you're signed in. See [Public API](#public-api).

Train the detection model once (downloads the real UNSW-NB15 dataset, ~32MB):
```bash
cd backend
./data/download.sh
python -m detection.train
```

One-time: create the bootstrap "default" organization and migrate any existing single-tenant data into it (safe to re-run):
```bash
python scripts/migrate_to_organizations.py
```

Grant yourself Admin — a **platform-wide** role, distinct from your **organization** role (owner/admin/member), needed for deployment-level actions like `/system/health` and `/users`:
```bash
python scripts/promote_admin.py you@example.com   # after signing up in the app once
```

On first login you'll be prompted to create an organization (or accept an invite) — every table is scoped to it, so there's no way to see or act on data outside the org you're currently in.

Send a test syslog message to the real UDP listener (default port 1514, override with `SYSLOG_PORT`):
```bash
logger -n 127.0.0.1 -P 1514 "Failed password for invalid user admin from 203.0.113.45"
```

### AI triage assistant (optional, local)
```bash
brew install ollama
ollama pull llama3.1:8b   # or another open-weight model that fits your hardware
```

No API keys, no billing accounts, no paid tier required to run this project end to end (a free Gmail App Password is needed only if you want email alerts).

---

## Testing

```bash
# Backend — needs a disposable Postgres (matches what CI uses)
docker run -d --name cyberguard-test-pg -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=cyberguard_test -p 5433:5432 postgres:16
cd backend && source venv/bin/activate
pip install -r requirements-dev.txt
TEST_DATABASE_URL="postgresql://postgres:postgres@localhost:5433/cyberguard_test" pytest -v

# Frontend
npm run test
```

CI (`.github/workflows/ci.yml`) runs both suites plus a production build on every push/PR — see the badge above.

---

## Public API

Full interactive docs — every endpoint, request/response schema, and auth requirement — are generated directly from the FastAPI app, not hand-written and liable to drift: run the backend and open **`/docs`** (Swagger UI) or **`/redoc`**.

Ingestion (`POST /events/ingest`) authenticates with a **per-organization API key**, created from Settings → Organization → API Keys. Only a SHA-256 hash is ever stored server-side — the raw key is shown exactly once, at creation, same pattern as GitHub/Stripe. Keys can be individually revoked; a revoked key is rejected immediately (`backend/tests/test_api_keys.py` proves this against the real endpoint, not a mock).

---

## Compliance evidence export

Settings → Organization → Compliance Evidence Export downloads a real ZIP (`incidents.csv`, `incident_notes.csv`, `threats.csv`, `audit_log.csv`) for a date range — the "show us what happened and how you responded" ask behind a SOC2/ISO27001 evidence request. Every admin action (settings changes, incident lifecycle, API key issuance/revocation, user role/ban changes, model retraining, factory resets) is now persisted to a queryable `audit_log` table, not just written to stdout — the export is only as real as that table, so making the audit trail durable was a prerequisite, not an afterthought.

---

## SSO

**What's real:** a "Continue with Google" button on the login page, using Better Auth's `signIn.social` — genuinely verified end to end by clicking it in a live browser and landing on `accounts.google.com`'s real consent screen ("Sign in to continue to neon.tech"), not just wired up and assumed to work. Neon Auth provides a shared, pre-configured Google OAuth client for every project, so this needed zero external setup — no Google Cloud Console, no client ID/secret to manage.

**What's not:** enterprise SAML/OIDC SSO, where each customer organization brings its own identity provider (Okta, Azure AD, etc.). Three things independently confirm this isn't available here, not just "not configured":
1. Live probing the auth server directly (`curl`) — `sso/register` and `saml-sso/register` both 404, `organization/*` and `admin/*` don't.
2. Reading `@neondatabase/auth`'s actual runtime source (not its TypeScript types, which are misleadingly broad) — `signInWithSSO` is hard-coded to always return an error: *"Better Auth does not support enterprise SAML SSO... Use signInWithOAuth() for OAuth providers instead."*
3. Probing other social providers the same way Google was confirmed — GitHub and Microsoft both return `PROVIDER_NOT_SUPPORTED`; only Google is enabled on this project.

So "SSO" here honestly means "social login via Google," not "bring your own enterprise IdP" — the two get conflated a lot in marketing copy, and this project isn't going to do that.

---

## Security

A pass over the codebase found and fixed two real, exploitable issues and closed several gaps that existed since earlier phases:

- **Fixed:** `GET /settings/notifications` returned the live Slack webhook URL and the webhook HMAC signing secret to *any* authenticated user, not just Admins — confirmed exploitable with a fresh, self-signed-up account, no privilege escalation needed. Now masked (`null`) for non-owner/admin org roles; every other field (enabled flags, recipients, channel name) stays visible since none of it is a credential. Regression-tested, including that a non-admin's read doesn't silently persist the mask over the real secret in the database.
- **Fixed:** `GET /system/health` only required being logged in — once multi-tenancy landed, that meant any user in any organization could read aggregate event/threat/incident counts across *every* organization on the deployment. Found while scoping endpoints for multi-tenancy, not by a separate audit pass. Now requires the site-wide Admin role.
- **Fixed:** `POST /events/ingest` had no authentication at all — anyone could inject fabricated threats and trigger real Slack/email/webhook alerts. Now requires a real per-organization `X-API-Key` (hashed at rest), with a legacy shared-key fallback (`INGEST_API_KEY`) kept for backward compatibility.
- **Fixed:** compliance export's date filter parsed a bare `end=YYYY-MM-DD` as that day's midnight — the *start* of the day, not the end — which silently excluded anything created later the same day. Found via live browser verification (an incident created seconds before export didn't appear in it), not a code read; regression-tested.
- **Added:** rate limiting (`slowapi`) — 60/min on ingest, 5/min on each alert-test endpoint — so the endpoints that send real messages to real destinations can't be used to spam a Slack channel or inbox.
- **Added:** a persisted, queryable audit log (`audit_log` table, `main.record_audit()`) for every settings change, incident lifecycle event, API key issuance/revocation, user role/ban change, model retrain, and factory reset — not just a log line that scrolls away. Backs the compliance export.
- **Added:** real multi-tenant data isolation — every domain table scoped to `organization_id`, verified server-side against `neon_auth.member` on every request, never trusted from a client-supplied value. See [Architecture](#architecture).
- **Reviewed and found clean:** no secrets ever committed to git (verified via `git log` on `.env` patterns), no raw string interpolation into SQL anywhere in the codebase (all queries parameterized), CORS scoped to the dev origin only.

---

## Roadmap

Ordered by what unlocks the most, not by calendar date.

**Done**
- [x] Minimal schema on Neon: log events, threats
- [x] Wire dashboard to real API data (8 of 8 pages — see Status)
- [x] Classical anomaly detection service on one log source, retrainable from the UI
- [x] Real authentication (Neon Auth) + role-based access
- [x] Real alert delivery: Slack webhook, email, generic webhook
- [x] Real incident management (CRUD, notes, status workflow, linked to threats)
- [x] Real user management (roles, enforced account suspension)
- [x] Automated tests + CI
- [x] Local AI triage assistant via Ollama
- [x] Basic security hardening (secrets handling, rate limiting, audit log, API-key auth on `/events/ingest`) — see [Security](#security)
- [x] Real log-source ingestion: UDP syslog receiver, made `Logs` real
- [x] Anomaly explainability UI (surface *why*, not just *that*)
- [x] Multi-tenant / organization support — real Neon Auth `organization` plugin, every table org-scoped
- [x] Public API with documentation — per-org API keys + FastAPI's real OpenAPI docs at `/docs`
- [x] Compliance evidence export — real ZIP of incidents/threats/audit log, backed by a persisted audit trail
- [x] SSO — real Google OAuth login (see [SSO](#sso) for the honest scope: not enterprise SAML)

**Later**
- [ ] Enterprise SAML/OIDC SSO — blocked on Neon Auth enabling the plugin for this project (confirmed not just "unconfigured" — see [SSO](#sso))
- [ ] Additional log-source integrations (cloud audit logs, EDR webhooks) beyond syslog
- [ ] MFA / configurable session policy (needs a Better Auth plugin not currently enabled)
- [ ] Scheduled auto-retraining + data-drift monitoring (today's retraining is real but manually triggered)

**Long-term / vision, not committed**
- [ ] Fine-tuned detection model trained on real accumulated data
- [ ] Multi-agent security operations (specialized agents per domain)
- [ ] Integration marketplace
- [ ] On-prem / self-hosted enterprise edition
- [ ] Managed SOC-as-a-service offering

---

## Contributing
Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the
dev setup, test requirements, and this project's one non-negotiable
convention: nothing ships half-wired without an honest "not implemented
yet" label. Please also read the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security
Found a vulnerability? Please report it privately — see [SECURITY.md](SECURITY.md)
rather than opening a public issue.

## License
Apache License 2.0. See `LICENSE` for details, and `NOTICE` for attribution.

## Maintained by
[Teevexa Ltd](https://www.teevexa.com)

## Contact
teevexa@gmail.com
