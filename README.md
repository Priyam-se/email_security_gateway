# Email Security Gateway & Phishing Detection Tool

Cybersecurity Internship Project — Codec Technologies  
**Project Topic 5:** Email Security Gateway with Phishing Detection

A multi-layered email security inspection pipeline written in Python 3. It scans raw `.eml` email files to detect phishing, sender spoofing, homoglyph domains, dangerous attachments, and urgency language before an email reaches an employee's inbox.

---

## Features

- **Header Authentication & Spoof Check:**
  - Reads `Authentication-Results` to check SPF and DKIM pass/fail statuses.
  - Detects sender address spoofing by checking if the visible `From:` matches the technical `Return-Path:` or `Reply-To:` addresses.
- **URL & Domain Inspection:**
  - Extracts web links from email body text.
  - Detects raw IP addresses used in links instead of domain names.
  - Flags typosquatting and visual homoglyph tricks (e.g., `paypa1` mimicking `paypal`).
- **Attachment Scanner:**
  - Flags dangerous executable extensions (`.exe`, `.scr`, `.vbs`, `.iso`, `.bat`, `.ps1`).
  - Catches double extension disguise tricks (e.g., `invoice.pdf.exe`).
  - Computes SHA-256 hashes of attachments for logging and threat intel.
- **NLP Text Urgency Detection:**
  - Uses `scikit-learn` (TF-IDF + Naive Bayes) with keyword heuristic fallback.
  - Detects psychological panic triggers common in phishing (account suspended, verify within 24 hours, unauthorized login).
- **Consolidated Scoring:**
  - Combines penalties from all checks into a single **0–100% Risk Score**.
  - Categorizes emails as `CLEAN` (allow), `SUSPICIOUS` (flag warning), or `MALICIOUS` (quarantine/block).

---

## Project Structure

```text
email_security_gateway/
├── samples/                       # Test .eml files covering clean and threat scenarios
│   ├── 01_clean_alert.eml         # Legitimate GitHub alert (Passes SPF/DKIM)
│   └── 02_urgent_phish.eml        # Phishing email (Fails SPF, homoglyph URL, urgency)
├── src/
│   ├── __init__.py
│   ├── parser.py                  # Extracts headers, text body, and links from .eml
│   ├── auth_checker.py            # Checks SPF, DKIM, and sender mismatches
│   ├── url_checker.py             # Detects typosquatting and homoglyphs
│   ├── attachment_checker.py      # Checks dangerous extensions and file hashes
│   ├── ml_detector.py             # Scikit-learn NLP urgency and panic word detector
│   └── gateway.py                 # Aggregates scores and sets verdict
├── main.py                        # CLI tool for single and batch scanning
├── requirements.txt               # Dependencies (scikit-learn, dnspython, requests)
└── README.md                      # Project documentation
```

---

## Setup & Requirements

1. **Clone the repository:**
   ```bash
   git clone https://github.com/<your-username>/email_security_gateway.git
   cd email_security_gateway
   ```

2. **Set up a virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## How to Run

### Scan a Single Email
```bash
python3 main.py -f samples/02_urgent_phish.eml
```

### Batch Scan an Entire Directory
```bash
python3 main.py -d samples/
```

---

## Sample Scan Output

```text
=========================================================
        Email Security Gateway & Phishing Analyzer       
=========================================================

[*] Batch scanning 2 email(s) in: samples/...

---------------------------------------------------------
File       : 01_clean_alert.eml
Subject    : [GitHub] Security advisory alert
From       : GitHub <notifications@github.com>
Risk Score : 0/100 (CLEAN)
Action     : ALLOW (Delivered to Inbox)

[+] No malicious indicators detected.
---------------------------------------------------------
File       : 02_urgent_phish.eml
Subject    : URGENT: Your PayPal account has been suspended!
From       : PayPal Support <security-notice@paypal-verify-alert.com>
Risk Score : 100/100 (MALICIOUS)
Action     : BLOCK (Quarantined at Gateway)

Threat Indicators Flagged:
  [!] SPF authentication failed
  [!] DKIM cryptographic signature check failed
  [!] Reply-To mismatch: replies directed to external domain 'evil-spoofer.net'
  [!] Typosquatting detected: resembles 'paypal' using character substitution (login-security.paypa1-account-update.com)
  [!] Social engineering triggers detected: immediately, unauthorized, 24 hours, restricted, verify your account
---------------------------------------------------------

=== Scan Summary ===
  Clean Emails       : 1
  Suspicious Emails  : 0
  Blocked / Malicious: 1
  Total Processed    : 2
```

---

## What I Learned from this Project

1. **Multi-Vector Inspection is Essential:** Attackers can bypass simple keyword filters or pass SPF on their own domain. A true gateway has to cross-correlate headers, link domains, and body text together to make an accurate decision.
2. **How Header Spoofing Works:** An email client typically displays whatever is in the `From:` header. Attackers use this to display `PayPal Support`, but checking `Reply-To:` and `Return-Path:` exposes where replies and bounces actually go.
3. **Homoglyph & Lookalike Attacks:** Attackers use visually similar characters (like `1` for `l` or `0` for `o`) to trick users into trusting a URL. Normalizing and character-swapping before dictionary matching is an effective defense.
4. **Machine Learning vs Heuristics:** Phishing attacks rely heavily on creating artificial panic. Using TF-IDF with Naive Bayes trained on urgency language reliably detects psychological manipulation even if the attacker alters specific words.

---

## License

MIT License
