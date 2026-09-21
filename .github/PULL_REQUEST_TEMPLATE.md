## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Checks

```sh
bun run scripts/unit-check.ts
bun run scripts/hook-check.ts
bun run scripts/corpus-check.ts
npx --yes --package typescript@7 tsc -p tsconfig.json
```

- [ ] All four pass locally.

## If this adds a detection rule

- [ ] One line in a `hooks/detect/rules/*.ts` group, per `CONTRIBUTING.md`.
- [ ] A case in `scripts/unit-check.ts`, with a synthetic value — never a real
      credential, and never one copied from a live service.
- [ ] Rule counts in `CONTRIBUTING.md` and `CLAUDE.md` updated.
- [ ] If the rule uses a capture group, `hooks/detect/rules/deny.ts` refuses the
      shapes it should not take.

## The invariant

- [ ] Every fake this change can produce still looks exactly like the real
      thing: same prefix, same length, same character classes. No
      `[REDACTED]`, no hash, no placeholder.
