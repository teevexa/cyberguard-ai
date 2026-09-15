# Security Policy

CyberGuard AI is a threat-detection dashboard, so we take reports about its
own security seriously — please report privately rather than opening a
public issue.

## Reporting a vulnerability

Email **teevexa@gmail.com** with:

- A description of the vulnerability and its potential impact
- Steps to reproduce it (a minimal repro is enormously helpful)
- The affected version/commit, if known

You'll get an acknowledgment within **5 business days**. We'll follow up
with an assessment and, if confirmed, a target timeline for a fix. Please
give us a reasonable window to ship a fix before any public disclosure —
we're happy to coordinate a disclosure date with you.

Please don't:
- Open a public GitHub issue for a suspected vulnerability
- Test against anyone's production deployment without their permission
- Access, modify, or exfiltrate data that isn't yours in the course of
  investigating a report

Good-faith security research conducted under this policy — limited to your
own local instance or a deployment you're explicitly authorized to test —
won't be treated as a violation of our terms.

## Supported versions

This project doesn't yet maintain long-term-support branches — security
fixes land on `main`. If that changes (e.g. once there are tagged
releases), this section will list which versions still receive patches.

## Scope

In scope: the code in this repository (`backend/`, `src/`).

Out of scope: the third-party services it integrates with (Neon Postgres,
Neon Auth / Better Auth, Slack, Gmail SMTP, Ollama) — please report
vulnerabilities in those directly to their own maintainers. Findings about
how *this project* uses them (e.g. a misconfigured auth check, a secret
handled unsafely) are very much in scope.
