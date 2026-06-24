# PhishLab Threat Model

## Scope

This threat model covers PhishLab itself — the risks of running the platform, not the phishing emails it analyzes. PhishLab is a defensive tool; this document ensures the tool itself does not become an attack surface.

## Assets

| Asset | Description | Sensitivity |
|---|---|---|
| Uploaded `.eml` files | May contain personal data, credentials, malicious content | High |
| Analysis results | Contain extracted indicators, findings, scores | Medium |
| SQLite database | Stores analysis history | Medium |
| YAML rules | Detection configuration | Low |
| Dashboard | Web interface served locally | Low |

## Threat Actors

| Actor | Motivation | Capability |
|---|---|---|
| Malicious email author | Exploit the analyzer itself via crafted `.eml` | Craft emails with malicious payloads |
| Local attacker | Access analysis results or uploaded files | Local system access |
| Network attacker | Intercept dashboard traffic or inject requests | Network-level access |

## Threats and Mitigations

### T1: Malicious attachment execution

**Risk:** A crafted `.eml` contains an executable attachment. If the analyzer executes it, the system is compromised.

**Mitigation:** PhishLab never executes, opens, or extracts attachments. Analysis is metadata-only: filename, extension, MIME type, size, SHA256 hash. The attachment payload is read only to compute the hash.

### T2: Malicious HTML rendering

**Risk:** A crafted `.eml` contains HTML with `<script>`, `<iframe>`, or remote image tags. If rendered in the dashboard, it could execute scripts or load remote resources.

**Mitigation:**
- Email HTML is parsed with BeautifulSoup for link extraction only
- Dashboard sanitizes HTML before rendering
- Scripts, iframes, objects, and active content are stripped
- Remote image loading is blocked by default

### T3: URL following / SSRF

**Risk:** The analyzer follows a URL in an email, triggering server-side request forgery or confirming the email was opened.

**Mitigation:** PhishLab never follows URLs. All URL analysis is done locally by parsing the URL string. No HTTP requests are made to analyzed domains.

### T4: Path traversal via file upload

**Risk:** A crafted filename like `../../etc/passwd.eml` overwrites files outside the upload directory.

**Mitigation:**
- Uploaded filenames are not trusted
- Internal filenames are UUID-based
- File extension is validated (`.eml` only)
- Upload directory is configurable and isolated

### T5: Denial of service via large files

**Risk:** An extremely large `.eml` file exhausts memory or disk.

**Mitigation:** File size limit is enforced (default 10 MB, configurable via `PHISHLAB_MAX_UPLOAD_SIZE_MB`).

### T6: Secret leakage in logs or reports

**Risk:** Email headers or bodies contain passwords, tokens, or API keys. If logged or included in reports, they leak.

**Mitigation:**
- `redaction.py` strips known secret patterns from outputs
- Full email bodies are not logged
- Headers with potential secrets are not logged verbatim
- Reports include redacted versions of sensitive fields

### T7: Cross-site scripting in dashboard

**Risk:** Analysis results rendered in the dashboard contain unescaped HTML.

**Mitigation:**
- React escapes output by default
- `dangerouslySetInnerHTML` is used only for sanitized previews
- Email content displayed in the dashboard is always escaped or sanitized

### T8: Local network exposure

**Risk:** The API or dashboard is accessible to other machines on the network.

**Mitigation:** Default bind address is `127.0.0.1` (localhost only). Network exposure requires explicit configuration change.

## Out of Scope

- PhishLab does not protect against compromise of the host machine itself
- PhishLab does not authenticate users in the MVP (single-user local tool)
- PhishLab does not encrypt the SQLite database (local-only assumption)
