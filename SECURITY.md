# Security Policy

API Relay Audit is a local security audit tool for third-party AI API relays
and LLM proxies. This policy covers vulnerabilities in this repository, not
findings about relay operators.

## Supported Version

The supported release line is the current `master` branch and the latest
published release. Older snapshots may be useful for comparison, but security
fixes land on `master` first.

## Reporting a Vulnerability

If you find a vulnerability in API Relay Audit itself, please open a private
security advisory on GitHub when available, or contact the maintainer before
publishing exploit details.

Please include:

- The affected file, command, or workflow.
- A minimal reproduction that does not expose real API keys.
- Whether the issue affects the standalone `audit.py`, the modular package, or
  both.
- Any evidence that a report could leak credentials, send traffic to an
  unintended host, or misclassify an unsafe relay as clean.

Do not include live credentials, private relay URLs, wallet seed phrases,
private keys, or user traffic captures.

## Scope

In scope:

- Credential leakage caused by this tool.
- Incorrect redaction or unsafe report handling.
- A bug that silently changes the target relay URL.
- A bug that marks an inconclusive or anomalous audit step as clean.
- Drift between the standalone and modular distributions that changes audit
  behavior.

Out of scope:

- A relay operator's behavior unless it demonstrates a bug in this tool.
- Requests for relay recommendations or rankings.
- Vulnerabilities in upstream AI providers.
- Results from modified forks that do not match this repository.

## Audit Findings Are Not Certifications

API Relay Audit reports evidence from local probes. A `LOW` result is not a
certificate that a relay is safe, and an `inconclusive` result is not clean.
Use the report as one input to a broader security review.
