# Training Mode

## Overview

PhishLab includes a training mode for phishing awareness education. Users are presented with sample emails and must decide whether each is phishing or legitimate. After answering, they receive an explanation of the correct answer and the indicators they should have noticed.

## How It Works

1. **Browse samples** - View a list of training emails with titles, difficulty levels, and tags
2. **Examine the email** - Read the email content, headers, and metadata
3. **Make a decision** - Answer "Phishing" or "Legitimate"
4. **Learn** - See the correct answer, explanation, and list of indicators

## Training Samples

PhishLab ships with at least 7 sample emails covering common phishing scenarios:

| Sample | Type | Difficulty | Scenario |
|---|---|---|---|
| Benign Newsletter | Legitimate | Beginner | Normal marketing email with proper headers |
| Fake Microsoft Alert | Phishing | Beginner | Account compromise alert with IP-based links |
| Invoice Phish | Phishing | Intermediate | Fake invoice with malicious attachment |
| Password Reset (Legit) | Legitimate | Intermediate | Real password reset with proper authentication |
| Shipping Notification Phish | Phishing | Beginner | Package delivery scam with shortened links |
| Bank Phish (Polish) | Phishing | Intermediate | Polish-language bank impersonation |
| Gift Card Scam | Phishing | Beginner | Boss impersonation requesting gift cards |

## Sample Structure

Each training sample includes:

```yaml
id: "fake-microsoft-alert"
title: "Microsoft Account Security Alert"
description: "An email claiming your Microsoft account was compromised"
eml_filename: "fake-microsoft-alert.eml"
is_phishing: true
difficulty: "beginner"
explanation: >
  This email impersonates Microsoft but was sent from micros0ft-alert.com
  (note the zero instead of 'o'). The link shows login.microsoft.com but
  actually points to an IP address. SPF and DMARC both fail.
indicators:
  - "Sender domain uses typosquatting (micros0ft-alert.com)"
  - "Return-Path domain differs from From domain"
  - "Link text shows microsoft.com but href is an IP address"
  - "SPF fail, DKIM none, DMARC fail"
  - "Urgency language: 'immediately', 'within 24 hours'"
  - "Account suspension threat"
tags:
  - "brand-impersonation"
  - "credential-phishing"
  - "urgency"
```

## Quiz Evaluation

```python
answer = QuizAnswer(
    sample_id="fake-microsoft-alert",
    user_answer=True,  # user says it's phishing
    correct=True,      # that's right
    explanation="..."  # shown after answering
)
```

## API Endpoints

- `GET /api/training/samples` - List all training samples with metadata (no explanations until answered)
- `GET /api/training/samples/{id}` - Get a specific sample's email content
- `POST /api/training/answer` - Submit an answer, receive correctness and explanation

## Educational Goals

Training mode is designed to help users develop these skills:

1. **Header inspection** - Check sender address, not just display name
2. **Link verification** - Hover before clicking, check the actual domain
3. **Authentication awareness** - Understand what SPF/DKIM/DMARC mean
4. **Language pattern recognition** - Identify urgency, threats, and unusual requests
5. **Attachment caution** - Recognize dangerous file types and double extensions
6. **Brand verification** - Spot typosquatting and domain impersonation

## Safety

- All sample emails are synthetic — no real personal data
- Samples are local `.eml` files, not fetched from external sources
- No emails are sent during training
- No credentials are collected
- Training is a local quiz, not a simulated phishing campaign
