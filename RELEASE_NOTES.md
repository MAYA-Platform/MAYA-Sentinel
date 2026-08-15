# MAYA Sentinel v1.0.0

The full static scanner release. MAYA Sentinel is a local repository ZIP scanner that surfaces risk signals before any code runs, with no execution, no installs, and no network calls.

## New in 1.0.0

- **Six scan modes** in the web UI and CLI (`--mode`): Safety Scan, Phishing / Impersonation, Dependency & Supply Chain, AI / Agent Surface, Exfil & Telemetry, Archive Safety. Pick a focus before you drop the ZIP; the report leads with what matters for your question.
- **Phishing and brand-impersonation detection surface** built from a real 2026 campaign that mass-mentioned GitHub users and redirected them to a fake `hermes-agent.icu`. Detects shortlink funnels, lookalike domains, scam ad/tracking stacks, credential-harvest and wallet-drainer wording, and exfiltration endpoints.
- **MIT License** replacing the previous beta evaluation license. Use, host, fork, and build on it freely.
- Public beta tags removed. This is the release line.

## Scanner capability

- Bounded ZIP intake and archive-safety checks
- Static signal scanning across credentials, binaries, install hooks, filesystem, process, network, phishing, and intrusiveness surfaces
- AI/component BOM and agent/MCP workflow surfaces
- Public-safe projection layer
- Markdown, HTML, and JSON receipts
- Local history and deletion controls
- Desktop and command-line launch paths
- Hardened loopback HTTP boundary and browser headers

## Boundaries

Static analysis only. No repository code execution, dependency installation, cloud upload, telemetry, malware-clearance claim, or production SLA.

## Prior beta lineage

- beta.3 (2026-08-15): phishing and brand-impersonation detection surface
- beta.2: mobile touch targets, middle-ellipsized scan IDs, browser permission hardening
- beta.1: initial public release, ZIP intake, static scanner, receipts
