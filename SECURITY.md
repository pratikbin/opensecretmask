# Security

## What osm protects against

osm is a **defence in depth** measure, not a boundary. It reduces the chance
that a credential reaches a model provider, a transcript, or a subagent. It
does not make that impossible.

Specifically, osm masks values it can **detect**, on the channels it **hooks**.
Everything else passes through untouched.

## What osm does not protect against

Do not rely on osm as the only thing between a credential and a third party.

- **An undetected secret is an unmasked secret.** A credential with no vendor
  prefix, no recognisable shape, and no entry in a scanned `.env` is invisible
  to the scanner. The entropy layer is off by default and, when on, is a
  heuristic.
- **A skipped hook fails open.** The engine runs core in place of a hook that
  throws or overruns its budget. osm answers for itself rather than letting the
  engine substitute, but a bug in that path serves the real value.
- **The store is plaintext.** With `persist: true` (the default), literal
  secrets are written to `~/.claude/plugins/store/osm_<key>-<hash>.json` with
  mode 644. See "Hardening this on a Mac" in the README.
- **A classic hook downstream of osm receives the restored value**, and the
  engine writes its stdout verbatim into the transcript. Nothing osm can do
  from inside.
- **osm is not a sandbox.** It does not stop a tool call from doing what the
  model asked, only from learning the credential's true value.

The README's guarantees section and `CLAUDE.md`'s "Engine facts" carry the
detail. `Open items` in `CLAUDE.md` is the current honest list of known gaps.

## Reporting a vulnerability

Report privately through
[GitHub Security Advisories](https://github.com/pratikbin/opensecretmask/security/advisories/new).
Do not open a public issue for a leak path.

Include the channel (which hook, which field), the shape of the value that
escaped, and a reproduction if you have one. A failing case in
`scripts/hook-check.ts` form is the most useful thing you can send.

Expect an acknowledgement within a week. There is no bounty.

A missing detection rule for a vendor is **not** a vulnerability — open a normal
issue, or send a PR per `CONTRIBUTING.md`.

## Supported versions

The latest release only. osm tracks the Claude Code function-hooks API, which
still moves.
