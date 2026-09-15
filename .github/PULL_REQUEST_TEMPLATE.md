## What this changes and why

<!-- The reasoning matters more than the diff — what problem does this solve? -->

## Testing

- [ ] `npm run test` passes
- [ ] `npx tsc --noEmit -p tsconfig.app.json` shows no new errors
- [ ] `npm run lint` shows no new errors
- [ ] Backend: `pytest` passes against a disposable Postgres (see CONTRIBUTING.md)
- [ ] Added/updated tests for the behavior this PR changes

## Honesty check

- [ ] Every button/endpoint this PR adds actually does what its label says —
      no wired-up UI for a feature that's still a stub (see CONTRIBUTING.md)
- [ ] If something here is intentionally partial, it's labeled as such in
      the UI/README, not left to look finished

## Anything reviewers should pay extra attention to?

<!-- e.g. "this touches org-scoping, please check the isolation tests" -->
