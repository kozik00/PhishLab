# Docker Setup for PhishLab

## Prerequisites

### Installing Docker Desktop on Windows

1. **Download Docker Desktop**
   - Go to https://www.docker.com/products/docker-desktop/
   - Click "Download for Windows"

2. **System Requirements**
   - Windows 10/11 (64-bit) Home, Pro, Enterprise, or Education
   - WSL 2 backend (recommended) or Hyper-V

3. **Enable WSL 2** (if not already enabled)
   Open PowerShell as Administrator:
   ```powershell
   wsl --install
   ```
   Restart your computer after this completes.

4. **Install Docker Desktop**
   - Run the downloaded installer
   - Ensure "Use WSL 2 instead of Hyper-V" is checked
   - Click "Ok" and wait for installation
   - Restart your computer

5. **Verify Installation**
   ```powershell
   docker --version
   docker compose version
   ```

## Running PhishLab with Docker

### Quick Start

```bash
cd C:\Users\PC\Desktop\PROJECTS\PhishLab
docker compose up --build
```

This starts two containers:
- **api** — FastAPI backend on port 8000 (internal)
- **dashboard** — React frontend + nginx on port 8080 (exposed)

Open http://localhost:8080 in your browser.

### Useful Commands

```bash
# Start in background
docker compose up -d --build

# View logs
docker compose logs -f

# View logs for one service
docker compose logs -f api

# Stop
docker compose down

# Stop and remove volumes (deletes analysis history)
docker compose down -v

# Rebuild after code changes
docker compose up --build
```

### Architecture

```
Browser :8080 --> nginx (dashboard container)
                    |
                    |--> /api/* --> FastAPI (api container) :8000
                    |
                    |--> /*     --> React SPA (static files)
```

### Data Persistence

Analysis data is stored in Docker named volumes:
- `phishlab-data` — SQLite database
- `phishlab-uploads` — Uploaded .eml files

These persist across container restarts. Use `docker compose down -v` to delete them.

### Troubleshooting

**"docker is not recognized"**
- Docker Desktop is not installed or not in PATH
- Restart your terminal after installing Docker Desktop

**"port 8080 already in use"**
- Edit `docker-compose.yml`, change `"8080:80"` to another port like `"9090:80"`

**Build fails on npm install**
- Ensure `apps/dashboard/package-lock.json` exists
- Run `cd apps/dashboard && npm install` locally first to generate it

**WSL 2 installation issues**
- Open PowerShell as Administrator: `wsl --update`
- If Hyper-V conflict: disable Hyper-V in Windows Features
