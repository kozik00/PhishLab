# PhishLab Portfolio Pitch

## What Is This?

PhishLab is a local-first email threat analysis platform. You give it a suspicious `.eml` file, and it tells you whether it's phishing — with evidence, a risk score, and actionable recommendations.

## Why I Built It

Phishing is the most common initial attack vector. Most people can't read email headers, don't know what SPF/DKIM/DMARC are, and can't tell a typosquatted domain from the real thing. I wanted to build a tool that makes email threat analysis accessible.

## What It Demonstrates

### Software Engineering

- **Modular architecture** - Core library, API, and dashboard are cleanly separated
- **Data modeling** - Pydantic models for type-safe email representation
- **Test-driven development** - pytest suite with synthetic fixtures covering normal, malformed, and adversarial inputs
- **Clean code** - Small, focused modules with clear responsibilities

### Security Knowledge

- **Email security** - SPF, DKIM, DMARC authentication analysis
- **Threat detection** - Header mismatches, URL analysis, typosquatting detection, content pattern matching
- **Defensive design** - No execution, no fetching, no exfiltration, secret redaction
- **Threat modeling** - Documented threats and mitigations for the tool itself

### Full-Stack Development

- **Backend** - Python, FastAPI, Pydantic, SQLite
- **Frontend** - React, TypeScript, Vite
- **DevOps** - Docker Compose, environment configuration
- **Documentation** - Architecture docs, threat model, security notes

### Domain Expertise

- **Email internals** - RFC 5322 headers, MIME multipart, content transfer encoding
- **Phishing techniques** - Brand impersonation, typosquatting, display name spoofing, URL obfuscation
- **Risk assessment** - Structured scoring model with transparent methodology

## Technical Highlights

1. **Parser handles adversarial input** - Malformed headers, missing fields, broken encodings — the parser never crashes
2. **7 independent analyzers** - Each produces structured findings with severity, evidence, and recommendations
3. **YAML-driven rules** - Detection patterns are configurable without code changes
4. **Bilingual detection** - Phishing patterns in both English and Polish
5. **Privacy-first** - Secret redaction, no logging of email content, local-only operation
6. **Training mode** - Built-in awareness quizzes with sample emails and explanations

## Stack

Python 3.11+ | FastAPI | Pydantic | BeautifulSoup | Jinja2 | React | TypeScript | Vite | SQLite | Docker Compose | pytest

## What I'd Add Next

- VirusTotal integration for attachment hash lookups (opt-in)
- URL reputation checking via safe APIs (opt-in)
- Machine learning-based content classification
- Multi-language support beyond English and Polish
- Playwright E2E tests for the dashboard
- PostgreSQL for multi-user deployment
