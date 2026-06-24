# Risk Scoring Model

## Overview

PhishLab calculates a phishing risk score from 0 to 100 based on the findings produced by all analyzers. The score indicates how likely an email is to be a phishing attempt.

## Risk Levels

| Score Range | Level | Interpretation |
|---|---|---|
| 0 - 30 | Low | Email appears legitimate or has minor anomalies |
| 31 - 60 | Medium | Email has suspicious indicators worth investigating |
| 61 - 80 | High | Email has strong phishing indicators |
| 81 - 100 | Critical | Email is almost certainly a phishing attempt |

## Scoring Method

### Base Severity Points

Each finding contributes points based on its severity:

| Severity | Points |
|---|---|
| Critical | +35 |
| High | +20 |
| Medium | +10 |
| Low | +4 |
| Info | +0 |

### Score Calculation

1. Sum the severity points from all findings
2. Cap the total at 100
3. Map the score to a risk level

```
score = min(100, sum(severity_points[f.severity] for f in findings))
```

### Category Scores

In addition to the overall score, PhishLab calculates per-category scores:

| Category | What it covers |
|---|---|
| Sender Identity | Header mismatches, display name impersonation |
| Authentication | SPF, DKIM, DMARC failures |
| Links | Suspicious URLs, domain mismatches |
| Attachments | Double extensions, suspicious file types |
| Content | Phishing language patterns |
| Brand Impersonation | Typosquatting, brand name abuse |

Each category score is the sum of severity points for findings in that category, uncapped.

### Top Contributors

The analysis result includes a `top_contributors` list — the titles of the highest-severity findings that most influenced the score. This helps users understand why the score is what it is.

## Examples

### Low Risk Email (Score: 4)

A legitimate newsletter with:
- Reply-To differs from From (common for newsletters) → Low (+4)

### Medium Risk Email (Score: 30)

A forwarded message with:
- Missing Authentication-Results → Medium (+10)
- HTTP link (no HTTPS) → Medium (+10)
- External domain in Reply-To → Medium (+10)

### High Risk Email (Score: 75)

A fake account alert with:
- From/Return-Path domain mismatch → High (+20)
- SPF fail → High (+20)
- IP-based URL → High (+20)
- Urgency language → Medium (+10)
- Account suspension threat → Low (+4)
- Missing HTTPS → Info (+0)
- Score: min(100, 74) = 74

### Critical Risk Email (Score: 100)

A credential phishing email with:
- Display text domain differs from href domain → Critical (+35)
- SPF fail + DKIM none + DMARC fail → High (+20 each = 60)
- Account suspension threat → Medium (+10)
- Credential request → Medium (+10)
- Brand impersonation (typosquatting) → High (+20)
- Score: min(100, 135) = 100

## Design Notes

- The scoring model is intentionally simple (weighted sum) to be transparent and explainable
- Scores are deterministic: same findings always produce the same score
- The model does not use machine learning — it is purely rule-based
- Tuning is done by adjusting severity assignments in individual analyzers
- Future versions may add confidence weighting: `score += points * finding.confidence`
