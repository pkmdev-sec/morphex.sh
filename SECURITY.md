# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in MORPHEX, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email [security@morphex.sh](mailto:security@morphex.sh) with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

We'll acknowledge receipt within 48 hours and aim to release a fix within 7 days for critical issues.

## Scope

This policy covers the MORPHEX scanner and its dependencies.

## What Counts

- Remote code execution via crafted input files
- Credential exfiltration (MORPHEX reading and leaking secrets it scans)
- Authentication bypass in the API server
- Path traversal in archive handlers
- Denial of service via crafted input

## What Doesn't Count

- False positives or false negatives in scan results (use GitHub Issues)
- Findings in MORPHEX's own test data (the `test/secrets/` directory contains intentional test credentials)
- Rate limiting configuration

## Recognition

We're happy to credit security researchers in our changelog. Let us know if you'd like to be credited or prefer to remain anonymous.
