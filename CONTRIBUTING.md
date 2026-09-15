# Contributing to CyberGuard AI

Thanks for considering a contribution. This project is maintained by
[Teevexa Ltd](https://www.teevexa.com). A few things that'll make the
process smoother for both of us.

## Before you start

For anything beyond a small fix — a new feature, a change to how
detection/alerting/multi-tenancy works, a dependency swap — please open an
issue first to discuss the approach. It's a much better use of your time
than a PR that turns out to need a different design.

For a small, obvious fix (a bug, a typo, a broken link), a PR without a
prior issue is fine.

## The one rule that matters most here: no fabricated capability

This codebase has a specific, deliberately-enforced convention: **the UI and
docs never claim something works, or is AI-powered, or is "real," unless it
actually is.** Look at how `Logs.tsx`, the README's status table, or the
Settings page's "not implemented" callouts are written — mock data, stubbed
endpoints, and partial features are always labeled as such, out loud, right
next to the thing that's incomplete. If your change can't be finished
end-to-end, either finish it, scope it down to a real slice that does work,
or land it behind an honest "not implemented yet" label — don't wire up a
button that doesn't do what it says.

## Development setup

See the [Local setup](README.md#local-setup) section of the README for
getting the frontend and backend running. Short version:

```bash
# Frontend
npm install
npm run dev

# Backend
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
python init_db.py
uvicorn main:app --reload
```

## Tests

Both suites are real and expected to pass before a PR merges — CI runs them
on every push. If you add a feature, add a test for it in the same PR
(browse `backend/tests/` or `src/**/*.test.ts(x)` for the existing style,
which favors testing real behavior over mocking everything in sight).

```bash
# Frontend
npm run test

# Backend — needs a disposable Postgres (see backend/tests/conftest.py)
docker run -d --name cyberguard-test-pg -e POSTGRES_PASSWORD=postgres -p 5433:5432 postgres:16
docker exec cyberguard-test-pg psql -U postgres -c "CREATE DATABASE cyberguard_test;"
cd backend && source venv/bin/activate
TEST_DATABASE_URL="postgresql://postgres:postgres@localhost:5433/cyberguard_test" python -m pytest
```

Also run, and fix anything they flag in files your PR touches:

```bash
npm run lint
npx tsc --noEmit -p tsconfig.app.json   # plain `tsc --noEmit` at the root checks 0 files — see tsconfig.json's project references
```

## Pull requests

- Keep PRs focused — one logical change per PR is easier to review and
  easier to revert if something's wrong.
- Explain *why*, not just *what*, in the description — the reasoning is
  what future readers (including you, in six months) actually need.
- Don't add speculative abstractions, config flags, or "might need this
  later" code for a feature that doesn't exist yet.
- Security-sensitive changes (auth, multi-tenancy boundaries, secrets
  handling) get extra scrutiny and may take longer to review — that's not
  personal, it's the nature of the subsystem.

## Reporting a security vulnerability

Please don't open a public issue — see [SECURITY.md](SECURITY.md).

## Code of Conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
