# MAYA Sentinel Safety Boundary

## Allowed behavior

- Bounded static inspection of a user-selected ZIP
- Temporary extraction only after archive safety validation
- Local public-projected Markdown, HTML, and JSON report generation
- Local retained receipt metadata and deletion controls

## Explicitly blocked

- Repository code execution
- Dependency installation
- Cloud upload or telemetry
- Account login
- External messaging, deployment, or publication
- Claims that a repository is safe, trusted, install-ready, or malware-free

## Data handling

Raw upload bytes and raw scan state are not persisted by default. Public-projected reports remain local until deleted. Sanitization is best-effort and is not comprehensive malware, secret, PII, or runtime-behavior detection.

## Local-server boundary

The application binds to loopback. Mutating requests require the active loopback Host, Origin, and an in-memory session token. Do not expose it beyond localhost or use it as a multi-user service.
