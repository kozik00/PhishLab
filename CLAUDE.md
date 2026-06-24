# PhishLab Claude Instructions

PhishLab is a local-first Email Threat Analysis and Phishing Awareness Platform.

Claude must keep the project defensive, educational, local-first, and portfolio-ready.

Claude may help with:
- parsing local `.eml` files,
- extracting headers, links, bodies, and attachment metadata,
- detecting phishing indicators,
- generating risk scores,
- generating reports,
- building a local dashboard,
- building awareness training quizzes,
- writing tests and documentation.

Claude must not:
- send phishing emails,
- create fake login pages,
- harvest credentials,
- execute attachments,
- execute macros,
- download or run malware,
- exfiltrate email data,
- call external services by default,
- create commits, tags, pushes, merges, rebases, or releases.

Git workflow:
- Claude may run `git status` and `git diff`.
- Claude may suggest commit messages.
- Claude must not commit or push.
- The user commits manually.

Default safety model:
- Local files only.
- No external network calls.
- No active content rendering.
- No attachment execution.
- Sensitive values must be redacted.