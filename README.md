# MAYA Repo Brief

**See what's inside a repo before you run it.**

Scan any file for hidden AI features, credential leaks, and security risks before
you install: ZIP, .exe, .msi, .apk, .dmg, .deb, .rpm, and more. 100% local, zero
execution, zero dependencies.

**What MAYA sees before repo code runs, now you can see it too.**

MAYA Repo Brief is a local repository ZIP scanner for bounded static analysis. It inspects archive structure and selected source signals, then produces public-safe Markdown, HTML, and JSON receipts, without executing repository code or installing a single dependency.

> Repo Brief cannot prove that a repository is safe. It identifies static signals that help a human decide what deserves deeper review.

![MAYA Repo Brief scan result](docs/images/repo-brief-result.png)

Upload a ZIP and watch the scan run, then read the decision brief.

## What it catches

- **ZIP traversal, path collision, symlink, device-name, compression-ratio, and extraction-budget hazards**, the archive tricks that hide malware in plain sight
- **Install hooks and dependency manifests**, what runs when you install
- **Credential-shaped values**, with redaction, not exposure
- **Process, filesystem, persistence, binary, and network string surfaces**, what the code reaches for
- **Phishing and brand-impersonation signals**, shortlink funnels, lookalike domains, scam ad/tracking stacks, credential-harvest and wallet-drainer wording, and exfiltration endpoints (built from a real 2026 campaign that mass-mentioned GitHub users and redirected them to a fake `hermes-agent.icu`)
- **Self-declared provenance and reuse signals**, is this actually what it claims to be?
- **AI/component inventory and agent/MCP workflow surfaces**, repo code that drives agents

Public conclusions are deliberately bounded to:

- `No signal detected by this scan`
- `Review`
- `Risk`
- `Blocked`

## Quick start

Requirements: Python 3.11, 3.12, or 3.13.

Windows:

```text
OPEN - MAYA Repo Brief.cmd
```

Any supported platform:

```bash
python maya_lens_server.py
```

Open `http://127.0.0.1:5182/` and choose a repository ZIP you are authorized to inspect.

No dependency installation is required.

## Command-line scan

```bash
python maya_lens_server.py --scan path/to/repository.zip
```

## Why it exists

AI-generated and AI-agent-driven code is everywhere now, and so is the
temptation to install first, inspect never. Repo Brief is the five-second
inspection layer: bounded, local, and honest about what it can and cannot prove.
The repo ecosystem is getting faster. Your review process should be, too.

## Verification

Every referenced test ships in this repository:

```bash
python -m py_compile src/maya_lens/*.py maya_lens_server.py
python tests/test_maya_lens_scanner.py
python tests/test_maya_lens_server.py
python tests/test_public_release_contract.py
node --check web/app.js
```

A ready-to-enable GitHub Actions template is included at `docs/ci/verify.yml.example`; local verification remains the release authority for this beta.

## Privacy and retention

- Uploaded ZIPs remain local and are removed after each scan attempt
- Raw scan state is memory-only by default
- Only public-projected reports and history metadata are retained locally
- Retained history and reports can be deleted through the UI
- The tool makes no repository network calls and sends no telemetry

## Security boundary

The server binds to loopback and uses Host, Origin, and in-memory session-token checks for mutating requests. It emits CSP, anti-frame, no-sniff, referrer, permissions, COOP, and CORP browser hardening headers.

## License

MAYA Repo Brief is distributed under the 2ndNatureAi Public Beta Evaluation License 1.0. See [LICENSE.txt](LICENSE.txt) for the full terms.

Copyright (c) 2026 2ndNatureAi.
