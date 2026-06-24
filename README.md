# PhishLab

Local-first Email Threat Analysis and Phishing Awareness Platform.

> **Legal Notice:** This project is intended only for defensive email analysis, awareness training, and educational use. Do not use it to send phishing emails, harvest credentials, execute attachments, or analyze emails without authorization.

## What Is PhishLab?

PhishLab is a defensive cybersecurity platform that analyzes suspicious email files, detects phishing indicators, calculates risk scores, generates reports, and provides awareness training through quizzes and sample emails.

It runs entirely on your local machine. No emails, links, attachments, or analysis results are sent to external services.

## Features

- **EML Parsing** - Import and parse local `.eml` files into a normalized model
- **Header Analysis** - Detect From/Reply-To/Return-Path mismatches, display name impersonation
- **Authentication Analysis** - Parse SPF, DKIM, and DMARC results from Authentication-Results headers
- **Link Analysis** - Detect display/target domain mismatch, IP-based URLs, shortened links, punycode, missing HTTPS
- **Domain Analysis** - Detect typosquatting and brand impersonation using Levenshtein distance
- **Attachment Analysis** - Metadata-only analysis: double extensions, suspicious file types, SHA256 hashes
- **Content Analysis** - Detect urgency language, credential requests, account suspension threats (English + Polish)
- **Risk Scoring** - Calculate phishing risk score from 0 to 100 with severity breakdown
- **Reports** - Generate JSON, Markdown, and HTML technical/user-friendly reports
- **Dashboard** - Upload emails and view analysis through a web interface
- **Training Mode** - Practice identifying phishing with sample emails, quizzes, and explanations

## Architecture

```
.eml file
  -> Email Parser
  -> Normalized Email Model
  -> Analyzer Orchestrator
      - Header Analyzer
      - Sender Identity Analyzer
      - Authentication Results Analyzer
      - Link Analyzer
      - Domain / Typosquatting Analyzer
      - Attachment Metadata Analyzer
      - Content Phishing Signal Analyzer
  -> Findings (severity, category, evidence, recommendation)
  -> Risk Scoring Engine (0-100)
  -> Report Generator (JSON, Markdown, HTML)
  -> Dashboard / CLI
  -> Training Mode
```

See [docs/architecture.md](docs/architecture.md) for the full architecture document.

## Project Structure

```
PhishLab/
├── packages/core/phishlab/     # Core analysis library
│   ├── models/                 # Pydantic data models
│   ├── parser/                 # .eml parsing, HTML extraction, attachment metadata
│   ├── analyzers/              # Header, auth, link, domain, attachment, content analyzers
│   ├── scoring/                # Risk scoring engine
│   ├── reports/                # Jinja2 report generation
│   ├── training/               # Training samples and quiz logic
│   └── utils/                  # Redaction, URL parsing, text helpers
├── apps/api/                   # FastAPI REST API
├── apps/dashboard/             # React dashboard
├── rules/                      # YAML rules (content patterns, brands, extensions)
├── examples/emails/            # Sample .eml files for demo and training
├── tests/                      # pytest test suite with .eml fixtures
└── docs/                       # Architecture, threat model, scoring, security docs
```

## Tech Stack

| Layer | Technology |
|---|---|
| Core library | Python 3.11+, Pydantic |
| Email parsing | Python `email` stdlib, BeautifulSoup4 |
| Rules/config | YAML (PyYAML) |
| Reports | Jinja2 templates |
| API | FastAPI |
| Database | SQLite (MVP) |
| Dashboard | React, Vite, TypeScript |
| Testing | pytest |
| Deployment | Docker Compose |

## Installation

### Prerequisites

- Python 3.11 or higher
- Node.js 18+ (for dashboard)

### Setup

```bash
# Clone the repository
git clone https://github.com/your-username/PhishLab.git
cd PhishLab

# Create a virtual environment
python -m venv .venv

# Activate (Linux/Mac)
source .venv/bin/activate

# Activate (Windows)
.venv\Scripts\activate

# Install the core library with dev dependencies
pip install -e "packages/core[dev]"
```

### Configuration

```bash
# Copy the example environment file
cp .env.example .env
```

## Usage

### Analyzing an Email (Python)

```python
from phishlab.parser import parse_eml_file

email = parse_eml_file("examples/emails/fake-microsoft-alert.eml")

print(f"From: {email.from_display_name} <{email.from_address}>")
print(f"Subject: {email.subject}")
print(f"Links found: {len(email.links)}")
print(f"Attachments: {len(email.attachments)}")

for link in email.links:
    flags = []
    if link.is_ip_based:
        flags.append("IP-based")
    if link.is_shortened:
        flags.append("shortened")
    if not link.uses_https:
        flags.append("no HTTPS")
    print(f"  {link.href} [{', '.join(flags)}]")
```

### Running Tests

```bash
# From project root, with venv activated
python -m pytest tests -v --rootdir .
```

### Running the API

```bash
pip install -e "apps/api"
uvicorn phishlab_api.main:app --reload
# API available at http://127.0.0.1:8000
# Interactive docs at http://127.0.0.1:8000/docs
```

### Running the Dashboard

```bash
cd apps/dashboard
npm install
npm run dev
# Dashboard available at http://localhost:5173
```

### Docker Compose (Recommended)

```bash
docker compose up --build
# Dashboard at http://localhost:8080
# API proxied through nginx at /api/
```

## Safety Model

PhishLab is designed with strict safety boundaries:

| Principle | Implementation |
|---|---|
| Local-first | No external network calls by default |
| No execution | Attachments are never opened, executed, or extracted |
| No fetching | URLs are parsed locally, never followed |
| No exfiltration | No data leaves your machine |
| Redaction | Secrets are redacted from logs and reports |
| HTML safety | Email HTML is sanitized before display |
| Upload safety | File type whitelist, size limits, safe internal filenames |

See [docs/security-notes.md](docs/security-notes.md) for the full security document.

## Limitations

- Does not perform live DKIM cryptographic verification (parses reported results only)
- Does not fetch URLs or check link destinations
- Does not scan attachments for malware (metadata-only analysis)
- Does not use external threat intelligence APIs in the MVP
- Content analysis uses pattern matching, not NLP/ML
- Polish language support is best-effort pattern matching

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| POST | `/api/analyze` | Upload and analyze an .eml file |
| GET | `/api/analyses` | List past analyses |
| GET | `/api/analyses/{id}` | Full analysis detail |
| GET | `/api/analyses/{id}/report?format=` | Download report (json, markdown, html, user) |
| GET | `/api/training/samples` | List training samples |
| GET | `/api/training/samples/{id}` | Get sample with email preview |
| GET | `/api/training/samples/{id}/analysis` | Run analysis on a sample |
| POST | `/api/training/answer` | Submit a single quiz answer |
| POST | `/api/training/quiz` | Submit full quiz |

## Roadmap

- [x] v0.1 - Core parser, models, test fixtures
- [x] v0.1 - All 7 analyzers with YAML rules
- [x] v0.1 - Risk scoring engine
- [x] v0.1 - Report generation (JSON, Markdown, HTML)
- [x] v0.1 - Training module with sample emails
- [x] v0.1 - FastAPI REST API
- [x] v0.1 - React dashboard
- [x] v0.1 - Docker Compose deployment
- [ ] v0.2 - CLI tool
- [ ] v0.2 - VirusTotal integration (opt-in)
- [ ] v0.2 - URL reputation checking (opt-in)
- [ ] v0.2 - Playwright E2E tests
- [ ] v0.3 - PostgreSQL support
- [ ] v0.3 - Multi-language content analysis

## License

MIT License. See [LICENSE](LICENSE).
