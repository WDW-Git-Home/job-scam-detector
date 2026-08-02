# Job Scam Detector v3.1

Automated email forensics tool for detecting recruitment scams, phishing attempts, and fraudulent job offers.

## Features

### Core Detection Engine (7 Signal Sources)

| Signal | Detection Method | Score Impact |
|--------|------------------|--------------|
| Known Scammer | Local SQLite database match | +25 pts |
| Authentication Failure | SPF / DKIM / DMARC missing | +30 pts |
| Young Domain | WHOIS age under 30 days | +15 pts |
| No MX Records | Domain can't receive email | +10 pts |
| Missing Website | Company website not found | +20 pts |
| Brand Impersonation | Fake company domain lookalike | +20 pts |
| Suspicious Route | High-risk country origin IP | +10-15 pts |

### Additional Detection

- PII Request Detection: SSN, DOB, driver's license, bank account requests
- Urgency Language: "Immediate", "ASAP", "urgent" pressure tactics
- Repeat Offender Tracking: SQLite database with PII redaction
- Email Backtracing: Received header parsing, public IP extraction, GeoIP lookup
- Recruiter Verification: Domain age, MX records, company website, email pattern analysis

## Architecture

scam-detector/
- scam_detector_core.py: Core scoring engine (all signals)
- scam_detector_db.py: SQLite database + PII redaction
- scam_detector_verify.py: Recruiter/domain verification
- scam_detector_backtrace.py: Email header backtracing + GeoIP
- scam-detector-gui.py: Desktop GUI (customtkinter)
- scam_detector_cli.py: Command-line interface
- requirements.txt: Python dependencies
- data/: GeoLite2 database for GeoIP

### Score Thresholds

| Score | Risk Level | Meaning |
|-------|-----------|---------|
| 0-20 | MINIMAL | No significant indicators |
| 21-40 | LOW | Some suspicious elements |
| 41-60 | MEDIUM | Multiple red flags |
| 61-80 | HIGH | Likely scam |
| 81-100 | CRITICAL | Confirmed or highly likely scam |

## Installation

    cd ~/Documents/scam-detector
    chmod +x *.py *.sh
    python3 -m pip install -r requirements.txt

### Dependencies

- customtkinter: GUI framework
- dnspython: DNS/MX record lookups
- python-whois: Domain WHOIS queries
- geoip2: MaxMind GeoLite2 integration

### GeoIP Setup (Optional)

1. Download MaxMind GeoLite2 Country database (free)
2. Place GeoLite2-Country.mmdb in data/ directory
3. Backtrace module activates automatically

## Usage

### GUI Mode

    python3 scam-detector-gui.py

Tabs:
- Single Scan: Paste email text or load .eml / .mbox files
- Batch Scan: Process folders of emails
- History: View past scan results (double-click for details)
- Demo Test Cases: Built-in test scenarios
- Settings: API keys, HTML report theme selector

GUI Features:
- File support: .eml, .mbox, and paste-from-clipboard
- Export: HTML (themed) or Plain Text
- 4 report themes: Batman Dark, Light Mode, Proton Purple, High Contrast
- Theme preference saved between sessions
- Copy report to clipboard
- VirusTotal + AbuseIPDB API key management

### CLI Mode

Analyze a Single Email:

    python3 scam_detector_cli.py analyze job-offer.eml --verbose

Verbose output includes:
- Authentication status (SPF, DKIM, DMARC)
- Domain age
- Red flag categories
- Recruiter verification (domain age, MX records, website)
- Email backtrace (origin IP, hops, geo location)
- Contributing factors

Batch Analyze a Folder:

    python3 scam_detector_cli.py batch ~/Documents/emails/ --verbose

Supports .eml and .mbox files (including multi-email .mbox).

Generate Reports:

    # HTML report (themed)
    python3 scam_detector_cli.py report job-offer.eml --output report.html --format html

    # JSON report (machine-readable)
    python3 scam_detector_cli.py report job-offer.eml --output report.json --format json

    # Markdown report (documentation/GitHub)
    python3 scam_detector_cli.py report job-offer.eml --output report.md --format markdown

CLI Help:

    python3 scam_detector_cli.py --help
    python3 scam_detector_cli.py analyze --help
    python3 scam_detector_cli.py batch --help
    python3 scam_detector_cli.py report --help

## API Keys (Optional)

- VirusTotal API: Domain reputation checks (free tier: 500/day)
  - Get key: https://www.virustotal.com/gui/join-us
- AbuseIPDB API: IP reputation checks (optional)
  - Get key: https://www.abuseipdb.com/

API keys are stored in ~/.config/scam_detector/config.json with restricted permissions (0o600).

## HTML Report Themes

Themes are selectable from the GUI Settings tab. Preference is saved to ~/.config/scam_detector/report_theme.json.

| Theme | Style |
|-------|-------|
| Batman Dark | Black bg, grey sections, yellow accent |
| Light Mode | White bg, dark text, purple accent |
| Proton Purple | Dark blue-purple bg, purple accents |
| High Contrast | Pure black, yellow text, green accent |

## Local Database

- Location: ~/.config/scam_detector/scan_history.db (SQLite)
- PII Redaction: Recipient emails, phone numbers, and SSNs are stripped before storage
- Repeat Offender Detection: Sender emails/domains with prior reports are flagged automatically
- Scoring impact: +5 (seen before), +15 (flagged), +25 (high risk)

## Disclaimer

This tool provides heuristic analysis only. Results do not constitute legal, financial, or professional advice. Always verify recruiter identities independently. This tool is not a substitute for professional cybersecurity advice.

## Author

Dave Wells, St. Louis MO
Job Scam Detector v3.1 (c) 2026

## License

MIT License - See LICENSE file
