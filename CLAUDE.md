# CLAUDE.md

Guidance for AI coding agents (Claude Code, Codex, Cursor, Copilot, Aider, …) working on this
repository. Other agents: treat this file as your project instructions too.

## Project

SessionLens records what a website does while someone browses it in real Google Chrome on macOS and
shows it as a step-by-step timeline: requests, cookie and storage changes, disk writes, screenshots.
It has three parts: a Chrome extension (recorder), a Python server (capture, analysis, export, API)
and a React analyzer UI.

## Layout

```
extension/     MV3 extension: background.js (webRequest/cookies/webNavigation), content.js (actions,
               storage), lib.js (pure helpers, unit-tested with node --test)
sessionlens/   Python package
  orchestrator.py  `start` / `view` / `setup`: launches tshark, Chrome, servers in order
  tshark.py        parses tshark JSON into wire events
  ingest.py        WebSocket endpoint the extension sends events to (127.0.0.1 only)
  model.py         Analysis: events -> steps, requests, cookie/storage rows, lineage (pure, no I/O)
  export.py        session.json + screenshots + bodies
  web.py           FastAPI API + static UI
  disk.py, cookies.py, bodies.py, replay.py, compare.py, session.py, config.py
web/src/       React + TypeScript analyzer (App, components/, state.ts, util.ts)
tests/         pytest suite; tests/fixtures/tshark_packets.json is real tshark output
docs/          export format, screenshots
```

## Commands

```bash
python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt
cd web && npm install && npm run build && cd ..

.venv/bin/pytest                 # Python tests
.venv/bin/ruff check .           # lint
.venv/bin/mypy                   # strict type check
node --test extension/lib.test.js
cd web && npm test && npm run lint && npm run typecheck && npm run build
```

All of these must pass before a change is done. Rebuild `web/` after UI changes (the server serves
`web/dist`).

## Conventions

- Python 3.12, ruff (line length 120) and `mypy --strict`. Dependencies pinned exactly in
  `requirements.txt`.
- TypeScript strict, no `any`, no non-null assertions; ESLint with react-hooks rules.
- Write the test first. `tests/test_model.py::session_events()` is the shared event fixture.
- `model.py` stays pure (events in, view out) so live and saved sessions render identically.
- Keep `web/src/types.ts` in sync with what `model.py` returns.
- Comments explain *why*, not what.

## Design rules (do not break)

- **Nothing may touch the page.** No `chrome.debugger`, no `--remote-debugging-*`, no automation
  flags, no proxy, no main-world scripts, no DOM changes. The extension only observes.
- The ingest port listens on 127.0.0.1 and only accepts the extension's origin plus the per-session
  claim nonce.
- Captures are written outside the repository (`SESSIONLENS_CAPTURES`, default
  `~/sessionlens-captures`). Never commit captures, `profiles/`, key logs or pcaps.
- Never put personal data (names, emails, accounts, local paths, real cookies or tokens) in code,
  tests, fixtures, docs or commit messages.
- macOS only; don't add platform branches without tests for them.
