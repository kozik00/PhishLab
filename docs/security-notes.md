# Security Notes

## Purpose

PhishLab is a defensive tool for analyzing suspicious emails. This document describes the security controls built into the platform to ensure it does not become an attack vector itself.

## Core Security Principles

### 1. Local-First

PhishLab makes no external network requests by default. All analysis is performed locally:
- URLs are parsed, not fetched
- Domains are checked against local brand lists, not DNS
- Attachments are hashed locally, not uploaded to scanning services
- Reports are generated locally, not sent to external services

Future integrations (VirusTotal, URL reputation) will be opt-in and require explicit configuration.

### 2. No Execution

PhishLab never executes any content from analyzed emails:
- Attachments are never opened, executed, or extracted
- Macros are never run
- Scripts in HTML are never executed
- Archive contents are never extracted in the MVP

### 3. No Fetching

PhishLab never follows URLs found in emails:
- No HTTP requests to link targets
- No DNS lookups for analyzed domains
- No image loading from email HTML
- No redirect following

### 4. Redaction

The `redaction.py` module strips known secret patterns from outputs:
- API keys
- Bearer tokens
- Authorization headers
- Passwords
- Private key blocks
- Session IDs and cookies
- Database URLs with credentials
- AWS access keys

Redaction is applied to report outputs. Full email bodies are never logged.

## File Upload Security

When the API accepts `.eml` file uploads:

| Control | Implementation |
|---|---|
| File type validation | Only `.eml` files accepted |
| Size limit | Configurable, default 10 MB |
| Filename safety | Internal filenames are UUID-based |
| Path traversal prevention | Uploaded filenames are never used for storage paths |
| Storage isolation | Uploads stored in a dedicated directory |

## HTML Safety

Email HTML displayed in the dashboard is sanitized:
- `<script>` tags are removed
- `<iframe>` tags are removed
- `<object>` and `<embed>` tags are removed
- Event handler attributes (`onclick`, `onerror`, etc.) are removed
- Remote image `src` attributes are blocked by default
- CSS `url()` references are blocked

The preferred display mode is extracted plain text, not rendered HTML.

## Dashboard Security

The dashboard runs locally and binds to `127.0.0.1` by default:
- Not accessible from other machines on the network
- No authentication in MVP (single-user local tool)
- CORS configured to allow only the local dashboard origin
- React's default output escaping prevents XSS

## Logging

PhishLab follows a minimal logging policy:
- Analysis events are logged at INFO level (email ID, timestamp, score)
- Full email bodies are never logged
- Full headers are never logged if they contain potential secrets
- Attachment payloads are never logged
- Finding evidence is logged but redacted for secrets

## What PhishLab Does NOT Do

This list exists to set clear expectations:

- Does not send emails of any kind
- Does not create phishing kits or fake login pages
- Does not harvest credentials
- Does not simulate phishing campaigns
- Does not bypass security tools
- Does not perform evasion, persistence, or stealth techniques
- Does not scan external systems or networks
- Does not upload data to external services by default
- Does not auto-execute any analyzed content

## Responsible Use

PhishLab is intended for:
- Analyzing emails you have received and are authorized to examine
- Education and awareness training
- Security research on your own systems
- Portfolio demonstration

PhishLab should not be used for:
- Analyzing emails without authorization
- Building phishing campaigns
- Creating attack tools
- Any activity that violates applicable laws

## Reporting Security Issues

If you discover a security vulnerability in PhishLab, please report it responsibly by opening a GitHub issue with the `security` label.
