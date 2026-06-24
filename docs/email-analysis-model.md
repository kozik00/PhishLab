# Email Analysis Model

## Overview

PhishLab parses `.eml` files into a `NormalizedEmail` model, then runs a series of analyzers that produce `Finding` objects. This document describes the data models and what each analyzer checks.

## NormalizedEmail Model

The `NormalizedEmail` is the central data structure produced by the parser. Every analyzer receives this model as input.

| Field | Type | Description |
|---|---|---|
| `message_id` | `str` | Message-ID header |
| `subject` | `str` | Email subject |
| `from_address` | `str` | Sender email address (lowercase) |
| `from_display_name` | `str` | Sender display name |
| `reply_to` | `str` | Reply-To address |
| `return_path` | `str` | Return-Path address |
| `to` | `list[str]` | Recipient addresses |
| `cc` | `list[str]` | CC addresses |
| `date` | `datetime | None` | Parsed date |
| `date_raw` | `str` | Raw Date header value |
| `received_hops` | `list[ReceivedHop]` | Parsed Received headers |
| `authentication_results` | `str` | Raw Authentication-Results header |
| `text_body` | `str` | Plain text body |
| `html_body` | `str` | Raw HTML body |
| `links` | `list[EmailLink]` | Extracted links from text and HTML |
| `attachments` | `list[EmailAttachment]` | Attachment metadata |
| `raw_headers` | `dict[str, list[str]]` | All headers as key-value pairs |

## EmailLink Model

| Field | Type | Description |
|---|---|---|
| `visible_text` | `str` | Text shown to user in the email |
| `href` | `str` | Actual URL target |
| `scheme` | `str` | URL scheme (http, https) |
| `domain` | `str` | Parsed hostname |
| `path` | `str` | URL path |
| `query` | `str` | Query string |
| `is_ip_based` | `bool` | Domain is an IP address |
| `is_shortened` | `bool` | Domain is a known URL shortener |
| `is_punycode` | `bool` | Domain uses punycode encoding |
| `uses_https` | `bool` | URL uses HTTPS |
| `display_domain` | `str` | Domain extracted from visible text |
| `target_domain` | `str` | Actual target domain |

## EmailAttachment Model

| Field | Type | Description |
|---|---|---|
| `filename` | `str` | Original filename |
| `content_type` | `str` | MIME content type |
| `size_bytes` | `int` | Payload size in bytes |
| `sha256` | `str` | SHA256 hash of payload |
| `extension` | `str` | File extension |
| `detected_extensions` | `list[str]` | All extensions found (for double extension detection) |
| `has_double_extension` | `bool` | File has multiple extensions |
| `is_suspicious_type` | `bool` | Extension is in the suspicious list |

## Finding Model

Each analyzer produces findings with this structure:

| Field | Type | Description |
|---|---|---|
| `id` | `str` | Unique identifier |
| `title` | `str` | Short description of the finding |
| `category` | `Category` | One of: sender_identity, authentication, links, attachments, content, brand_impersonation |
| `severity` | `Severity` | One of: critical, high, medium, low, info |
| `description` | `str` | Detailed explanation |
| `evidence` | `str` | Specific data that triggered the finding |
| `recommendation` | `str` | Suggested action |
| `location` | `str` | Where in the email the issue was found |
| `confidence` | `float` | 0.0 to 1.0 confidence level |
| `tags` | `list[str]` | Additional labels |

## Analyzers

### Header Analyzer

Checks for identity mismatches in email headers:
- From domain vs Reply-To domain mismatch
- From domain vs Return-Path domain mismatch
- Missing or suspicious Message-ID
- Display name impersonation patterns

### Authentication Results Analyzer

Parses the `Authentication-Results` header for:
- SPF pass, fail, softfail, none
- DKIM pass, fail, none
- DMARC pass, fail, none
- Missing authentication results entirely

### Link Analyzer

Analyzes extracted URLs without following them:
- Display text domain differs from href domain
- IP-based URLs
- Shortened URLs (bit.ly, tinyurl.com, etc.)
- Missing HTTPS
- Punycode domains
- Excessive subdomains
- Suspicious keywords in URL path

### Domain / Typosquatting Analyzer

Checks domains against a known brand list:
- Levenshtein distance <= 2 from known brands
- Common character substitutions (o/0, l/1/I, a/@)
- Hyphenated brand names
- Suspicious keywords near brand names (login, security, verify, account)

### Attachment Metadata Analyzer

Analyzes attachment metadata without opening files:
- Double extensions (e.g., `invoice.pdf.exe`)
- Suspicious executable extensions (.exe, .scr, .bat, .js, .vbs, .ps1)
- Macro-capable Office formats (.docm, .xlsm, .pptm)
- MIME type vs extension mismatch
- SHA256 hash computation

### Content Phishing Signal Analyzer

Scans subject and body text for phishing patterns:
- Urgency pressure ("immediately", "within 24 hours")
- Account suspension threats
- Credential requests ("verify your identity", "confirm your password")
- Payment/invoice language
- Gift card language
- Requests to open attachments or enable macros
- Impersonation of support, security, or billing teams

Supports English and Polish phrases.

## Parser Details

The parser uses Python's standard `email` library with `email.policy.default`:
- Handles multipart emails (alternative, mixed, related)
- Extracts text/plain and text/html parts
- Uses BeautifulSoup to extract links from HTML
- Extracts URLs from plain text via regex
- Deduplicates links by href
- Handles charset detection and safe decoding
- Gracefully handles malformed emails without crashing
