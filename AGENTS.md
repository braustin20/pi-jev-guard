# Agent development guide

## Repository map

- `src/index.ts` — Pi hooks, runtime state, fail-closed interception, slash commands
- `src/config.ts`, `src/defaults.ts`, `config.schema.json` — strict policy loading and tighten-only project merges
- `src/normalize.ts`, `src/paths.ts`, `src/shell.ts`, `src/redaction.ts` — local normalization and privacy boundary
- `src/deterministic.ts` — deterministic hazard findings
- `src/credentials.ts` — environment and secure user-local credential-file resolution
- `src/jev.ts` — TypeSafe SDK adapter and atomic Noul question battery
- `src/policy.ts` — decision precedence and failure behavior
- `src/approval.ts`, `src/audit.ts` — approval UI and sanitized session records
- `test/` — offline unit/integration tests; `live-evaluation.test.ts` is opt-in only

## Development commands

```sh
npm ci
npm run typecheck
npm test
npm run check
```

Run live evaluation only when explicitly requested and a local `TYPESAFE_API_KEY` is available:

```sh
PI_JEV_GUARD_LIVE=1 npm run test:live
```

## Safety invariants

- Never commit API keys, credentials, `.env` files, audit/session data, absolute user paths, or real global/project policy files.
- Read the API key only from `TYPESAFE_API_KEY` or `typesafeApiKey` in the fixed user-local `pi-jev-guard/settings.json` file under an absolute `XDG_CONFIG_HOME` (falling back to `~/.config`); do not add credential fields to policy configuration or project-local files.
- Environment credentials take precedence. Parse the user-local settings as strict JSON—never source or execute it—and preserve parent-directory and file owner/mode, regular-file, size, and no-symlink checks.
- Keep `@typesafe-ai/sdk` pinned exactly and retain the lockfile.
- Reject unknown configuration fields. Project policy stays tighten-only unless global policy explicitly allows relaxation.
- Use `path.relative` containment and canonicalize existing paths/nearest existing parents. Do not replace this with string-prefix checks.
- Do not send `read`, `write`, or `edit` file contents by default. Keep SDK logging at `warn`, `error`, or `off`; never enable `debug` in policy.
- Raw arguments may be hashed locally for exact session approvals, but must not be written to audit entries.
- Classification failure, cancellation, invalid policy, and unavailable approval UI must preserve fail-closed behavior.
- Deterministic code owns path arithmetic, shell operators, known destructive forms, and hard blocks. Jev evaluates narrow independent hazards; do not ask it for a combined risk score.
- Preserve decision precedence documented in `README.md` and test every change to it.
- `user_bash` denial must return a synthetic exit code `126`; `tool_call` denial must return `{ block: true, reason }`.
- Keep the package load-last warning in documentation because Pi has no hook-priority mechanism.

## Change guidance

- Add or alter configuration in all three places: TypeScript types/defaults, `config.schema.json`, and tests.
- Add deterministic detections with focused positive and benign cases to limit false positives.
- Keep normal tests offline and deterministic. Live model thresholds belong in the labeled live corpus.
- Before changing Pi integration, consult the installed Pi extension docs and type declarations for the target version.
- Before changing Jev calls, verify the pinned SDK declarations in `node_modules/@typesafe-ai/sdk/dist/` and official TypeSafe docs.
