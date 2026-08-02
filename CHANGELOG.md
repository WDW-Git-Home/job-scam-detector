# Changelog

All notable changes to Job Scam Detector will be documented in this file.

## v3.1 (August 2, 2026)

### Added
- Local SQLite database for repeat offender detection (scam_detector_db.py)
  - PII redaction before storage (emails, phone numbers, SSNs stripped)
  - Scoring: +5 (seen), +15 (flagged), +25 (high risk)
- Recruiter verification module (scam_detector_verify.py)
  - Domain age check via WHOIS (+15 pts if under 30 days)
  - MX record validation (+10 pts if missing)
  - Company website existence check (+20 pts if missing)
  - Email pattern analysis (+10 pts if suspicious)
- Email backtracing module (scam_detector_backtrace.py)
  - Received header parsing for origin IP extraction
  - Private IP filtering (RFC 1918)
  - MaxMind GeoLite2 integration for country-level geo lookup
  - Suspicious route detection (+10-15 pts for high-risk countries)
- HTML report theme selector in GUI Settings tab
  - 4 themes: Batman Dark, Light Mode, Proton Purple, High Contrast
  - Theme preference saved to ~/.config/scam_detector/report_theme.json
- CLI export formats: JSON and Markdown (in addition to HTML)
  - JSON: machine-readable for scripts and automation
  - Markdown: for documentation and GitHub issues
- .mbox file support in GUI file browser
- Maintenance script (maintenance.sh)
  - GeoIP database age check (warns if over 90 days)
  - SQLite vacuum
  - Config backup
  - Dependency check
  - Cache cleanup
- CLI check-updates command for dependency and GeoIP status
- Regression test suite (test_scam_detector.py)
- Comprehensive README.md with full v3.1 documentation

### Fixed
- Removed stray backtrace code from scam_detector_verify.py that caused NameError
- Fixed indentation errors in scam_detector_core.py (brand impersonation block)
- Fixed indentation errors in scam_detector_backtrace.py (class methods)
- Fixed export dialog defaulting to HTML when TXT selected
- Fixed file dialog missing .mbox option
- Fixed export button label referencing PDF (no PDF support exists)
- Fixed theme selector overlapping About section in Settings tab
- Fixed nested double quotes in f-strings causing syntax errors
- Fixed CLI findings dict missing raw_email, sender_name, company_name
- Fixed CLI verbose output missing verification and backtrace sections

### Changed
- calculate_threat_score now aggregates 7 signal sources
- GUI results display includes Recruiter Verification and Email Backtrace panels
- HTML report completely redesigned with themed CSS
- CLI verbose output expanded with verification and backtrace details
- Dark theme renamed to Batman Dark with black/grey/yellow palette
- Proton Purple theme differentiated from Dark theme
- Theme label updates dynamically when switching themes
- Export dialog opens to Documents instead of app folder

## v3.0 (July 2025)

### Added
- GUI with customtkinter (Single Scan, Batch, History, Demo tabs)
- CLI with analyze, batch, report subcommands
- SPF/DKIM/DMARC authentication checking
- Domain age via WHOIS
- Red flag pattern matching (PII requests, urgency language)
- HTML report export
- Scan history with SQLite storage
- VirusTotal and AbuseIPDB API integration
- Reply template drafts
- Batch analysis for folders

## v2.0 (Early 2025)

### Added
- Basic email parsing (.eml support)
- Simple threat scoring
- Terminal output

## v1.0 (Late 2024)

### Added
- Initial concept: paste email text, get basic flags
