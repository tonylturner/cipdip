# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in CIPDIP, please report it through [GitHub Security Advisories](https://github.com/tonylturner/cipdip/security/advisories/new).

Please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

Do not open a public issue for security vulnerabilities. We will acknowledge receipt within 48 hours and provide an initial assessment within 7 days.

## Scope

CIPDIP is a test harness for evaluating DPI engines and protocol implementations. Security issues in scope include:

- Path traversal in transport operations
- Command injection via configuration or CLI inputs
- Credential exposure in logs, outputs, or artifacts
- Authentication bypass in SSH transport

## Out of Scope

- Vulnerabilities in the CIP/ENIP protocol itself (these are the subject of testing, not bugs)
- Issues requiring physical access to test lab equipment
