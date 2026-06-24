# PhishLab Architecture

## Overview

PhishLab is a modular, local-first platform for email threat analysis. The architecture separates concerns into three layers: a core analysis library, an API layer, and a dashboard layer.

## Layers

### Core Library (`packages/core/phishlab/`)

The core library is a standalone Python package with zero web framework dependencies. It can be used independently as a library, from a CLI, or through the API.

**Submodules:**

| Module | Responsibility |
|---|---|
| `models/` | Pydantic data models for emails, findings, analysis results, and training |
| `parser/` | Parse `.eml` files into `NormalizedEmail` models |
| `analyzers/` | Independent analyzers that produce `list[Finding]` |
| `scoring/` | Calculate risk score (0-100) from findings |
| `reports/` | Generate JSON, Markdown, and HTML reports via Jinja2 |
| `training/` | Training sample library and quiz evaluation |
| `utils/` | Redaction, URL parsing, text normalization |

### API Layer (`apps/api/`)

FastAPI application that wraps the core library with REST endpoints:

- `POST /api/analyze` - Upload and analyze an `.eml` file
- `GET /api/analyses/{id}` - Retrieve a stored analysis
- `GET /api/analyses/{id}/report` - Download a report (JSON, Markdown, or HTML)
- `GET /api/training/samples` - List training samples
- `POST /api/training/answer` - Submit a quiz answer

The API stores analysis results in SQLite. It adds file upload handling, CORS, and request validation, but delegates all analysis logic to the core library.

### Dashboard Layer (`apps/dashboard/`)

React + Vite + TypeScript single-page application:

- File upload page
- Analysis results page (risk score card, findings, headers, links, attachments)
- Training mode page (sample emails, quiz, explanations)
- Report download

The dashboard communicates exclusively through the REST API. It never accesses the core library directly.

## Data Flow

```
User uploads .eml file
         │
         ▼
    ┌─────────┐
    │  Parser  │  email stdlib + BeautifulSoup
    └────┬────┘
         │
         ▼
  NormalizedEmail (Pydantic model)
         │
         ▼
┌─────────────────┐
│   Orchestrator   │  Runs all analyzers
└────────┬────────┘
         │
    ┌────┼────┬────────┬──────────┬──────────┬──────────┐
    ▼    ▼    ▼        ▼          ▼          ▼          ▼
 Headers Auth Links  Domains  Attachments  Content  Sender
    │    │    │        │          │          │        Identity
    └────┴────┴────────┴──────────┴──────────┴──────────┘
         │
         ▼
   list[Finding]
         │
         ▼
  ┌──────────────┐
  │  Risk Scorer  │  Weighted sum, capped at 100
  └──────┬───────┘
         │
         ▼
  AnalysisResult
         │
    ┌────┴────┐
    ▼         ▼
  SQLite   Reports
  storage  (JSON/MD/HTML)
```

## Design Decisions

### Why a separate core library?

The core library has no dependency on FastAPI, SQLite, or any web framework. This means:
- It can be tested independently with `pytest`
- It can be used from a CLI without running a server
- It can be imported into other Python projects
- The API layer is a thin wrapper, not a monolith

### Why individual analyzers?

Each analyzer is a standalone module that accepts a `NormalizedEmail` and returns `list[Finding]`. This means:
- Each analyzer can be tested in isolation
- Analyzers have no cross-dependencies
- New analyzers can be added without modifying existing ones
- Analyzers can be enabled/disabled independently

### Why YAML rules?

Content patterns, brand lists, suspicious extensions, and link shortener domains are defined in YAML files under `rules/`. This means:
- Non-developers can tune detection rules without touching Python code
- Rules can be version-controlled and reviewed independently
- Different rule sets can be swapped for different use cases

### Why Jinja2 for reports?

Reports are generated from Jinja2 templates. This separates presentation from analysis logic:
- Templates can be customized without modifying the report generator
- Multiple output formats (Markdown, HTML) share the same data
- Adding a new report format requires only a new template

### Why SQLite for MVP?

SQLite requires no external process, no configuration, and no credentials. It stores analysis results so the dashboard can retrieve them. PostgreSQL support is planned for v0.3.

## Security Architecture

See [security-notes.md](security-notes.md) for the full security document.

Key architectural constraints:
- No network calls from the core library
- No attachment execution or extraction
- No URL following or fetching
- Secrets are redacted from all outputs
- HTML is sanitized before display
- File uploads are validated and stored with safe filenames
