# MAYA Repo Brief v0.2.0-beta.3

Phishing and brand-impersonation detection surface, built from a real 2026-08-15 campaign.

## Added in beta.3

- **Phishing Surface axis**: flags shortlink funnels, lookalike domains, brand-impersonation hosts, scam ad/tracking stacks (Yandex Metrika, mail.ru counters, digitalcaramel, ad-fraud networks), credential-harvest and wallet-drainer wording, and exfiltration endpoints (Discord webhooks, Telegram bots, paste/transfer hosts)
- **Escalation rules**: multiple phishing signals co-occurring with process/network/credential surface route to `block_review_before_any_run`; a lone signal routes to advisory enrichment
- **False-positive control**: documentation references stay advisory; code/HTML signals carry the weight
- Regression coverage: live campaign reproduction, docs-reference advisory lane, clean-repo no-signal

## Added in beta.2

- Guaranteed 44px **Clear all** touch target at mobile widths
- Middle-ellipsized visible history scan IDs for calmer mobile layouts
- Full scan IDs preserved in title, accessibility labels, and deletion controls
- Explicit browser permission denial for Bluetooth and Serial APIs
- Focused private-source and standalone regression coverage

## Existing beta capabilities

- Bounded ZIP intake and archive-safety checks
- Static signal scanner
- Public-safe projection layer
- Markdown, HTML, and JSON receipts
- Local history and deletion controls
- Desktop and command-line launch paths
- Hardened loopback HTTP boundary and browser headers

## Boundaries

Static analysis only. No repository code execution, dependency installation, cloud upload, telemetry, malware-clearance claim, or production SLA.
