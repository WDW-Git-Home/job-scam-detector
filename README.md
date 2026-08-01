# Job Scam Detector v3.0

Automated email forensics tool for detecting recruitment scams, phishing attempts, and fraudulent job offers.

## Features

- Single Scan: Paste email text or load .eml / .mbox files
- Batch Analysis: Process folders of emails (supports .eml + multi-email .mbox)
- HTML Reports: Generate forensic reports with disclaimers
- Reply Drafts: Professional response templates for different scenarios
- Terminal Logging: Debug output toggle for troubleshooting
- Click-to-View: Double-click batch results for detailed reports

## Installation

cd ~/Documents/scam-detector
chmod +x *.py *.sh
python3 -m pip install -r requirements.txt

## Usage

GUI Mode:
  python3 scam-detector-gui.py

CLI Mode:
  python3 scam_detector_cli.py analyze job-offer.eml --verbose
  python3 scam_detector_cli.py batch ~/Documents/emails/
  python3 scam_detector_cli.py report job-offer.eml --output report.html
  python3 scam_detector_cli.py reply --template 1

## API Keys (Optional)

- VirusTwo API — Domain reputation checks (free tier: 500/day)
- AbuseIPDB API — IP reputation checks (optional)

Get keys from:
- VirusTwo: https://www.virustotal.com/gui/join-us
- AbuseIPDB: https://www.abuseipdb.com/

## Disclaimer

This tool provides heuristic analysis only. Results do not constitute legal, financial, or professional advice. Always verify recruiter identities independently.

## Author

Dave Wells, St. Louis MO
Job Scam Detector v3.0 (c) 2026

## License

MIT License — See LICENSE file
# job-scam
