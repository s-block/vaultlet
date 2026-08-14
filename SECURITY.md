# Security Policy

## Supported versions

Until Vaultlet reaches 1.0, security fixes are released only for the latest published
minor version. Upgrade to the newest release before reporting a problem that may
already have been corrected.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | No |

## Report a vulnerability

Do not disclose suspected vulnerabilities in a public issue, discussion, pull
request, or social-media post. Submit a private report through
[GitHub Private Vulnerability Reporting](https://github.com/s-block/vaultlet/security/advisories/new)
with:

- the affected Vaultlet version, operating system, Python version, and storage engine;
- a minimal reproduction or proof of concept;
- the expected and observed security impact; and
- any suggested remediation or disclosure constraints.

Reports should receive an acknowledgement within five business days. The maintainer
will investigate, coordinate a fix and release where appropriate, and credit the
reporter unless anonymity is requested. Please allow a reasonable remediation window
before public disclosure.

The security model and explicitly excluded threats are documented in
[docs/Security.md](docs/Security.md).
