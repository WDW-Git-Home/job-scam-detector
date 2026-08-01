#!/usr/bin/env python3
"""
scam_detector_core.py
Core analysis functions for Job Scam Detector
Imported by scam-detector-gui.py
"""

import os
import sys
import re
import json
import time
import subprocess
import urllib.request
import urllib.parse
import urllib.error
from email import policy
from email.parser import BytesParser, Parser
from datetime import datetime, timezone
from pathlib import Path

# ============================================================================
# CONFIGURATION
# ============================================================================

VERSION = "3.0"
CONFIG_DIR = Path.home() / ".config" / "scam-detector"
CONFIG_FILE = CONFIG_DIR / "config.json"
LOG_DIR = Path.home() / "Documents" / "logs" / "scam-detector"

CONFIG_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Red flag patterns (same as v2.0)
RED_FLAGS = {
    'pii_requests': {
        'weight': 30,
        'keywords': [
            r"driver'?s?\s*licen[cs]e",
            r"social\s*security",
            r"\bssn\b",
            r"date\s*of\s*birth",
            r"\bdob\b",
            r"passport",
            r"bank\s*account",
            r"routing\s*number",
            r"credit\s*report",
            r"background\s*check.*fee",
            r"send\s+(?:a\s+)?copy\s+of\s+(?:your\s+)?id",
            r"copy\s+of\s+(?:your\s+)?(?:license|passport|id)",
            r"dl\s*copy",
            r"last\s*4\s*digits.*ssn",
            r"date\s*of\s*birth.*dd/mm/yyyy",
        ],
        'description': 'Requests for Personally Identifiable Information (PII)'
    },
    'payment_requests': {
        'weight': 35,                              # Increased from 30
        'keywords': [
            r"processing\s*fee",
            r"application\s*fee",
            r"training\s*fee",
            r"equipment\s*fee",
            r"wire\s+transfer",
            r"wire\s+\$\d+",                       # NEW: "wire $2,500"
            r"wire\s+[\d,]+",                      # NEW: "wire 2500"
            r"send\s+money\s+to",                  # NEW: wire instruction
            r"send\s+funds\s+to",                  # NEW: wire instruction
            r"send\s+a\s+(?:wire|transfer)",       # NEW: wire instruction
            r"wires?\s+\$?[\d,]+",                 # NEW: "wire $X" or "wire X"
            r"bitcoin",
            r"crypto\s*wallet",
            r"gift\s*card",
            r"western\s*union",
            r"money\s*gram",
            r"deposit\s*it",                       # NEW: "deposit it and wire"
            r"deposit\s*the\s+check",              # NEW: "deposit the check"
            r"check.*deposit",                     # NEW: check-wiring pattern
            r"check.*wire",                        # NEW: check-wiring pattern
            r"wire.*deposit",                      # NEW: check-wiring pattern
            r"deposit\s*(?:is\s*)?required",
            r"pay\s*(?:a\s*)?fee",
            r"upfront\s*payment",
            r"overpaid",                           # NEW: common in scam scenarios
            r"return\s+(?:the\s+)?difference",     # NEW: overpayment scam language
        ],
        'description': 'Requests for payment or fees'
    },
    'urgency_language': {
        'weight': 15,
        'keywords': [
            r"immediate\s*start",
            r"start\s*tomorrow",
            r"urgent",
            r"respond\s*immediately",
            r"limited\s*time",
            r"act\s*now",
            r"don'?t\s*miss",
            r"positions?\s*(?:are\s*)?filling\s*fast",
            r"first\s*come\s*first\s*serve",
            r"at\s*the\s*earliest",
            r"without\s*any\s*delay",
            r"schedule.*without.*delay",
            r"scheduling.*asap",
        ],
        'description': 'Urgency or pressure tactics'
    },
    'salary_red_flags': {
        'weight': 15,
        'keywords': [
            r"\$\s*\d{3}[,.]?\d{3}\+?",
            r"\d{3}k\s*(?:per|a|/)\s*year",
            r"competitive\s*(?:salary|pay|rate)",
            r"unlimited\s*earnings?",
            r"no\s*experience\s*(?:needed|required|necessary)",
            r"work\s*from\s*home.*\$\d",
            r"weekly\s*pay.*\$\d",
            r"guaranteed\s*(?:income|pay|placement)",
            r"\$\d{2}/hr\s*(?:c2c|w2|all.?inclusive)",
            r"strict\s*budget",
        ],
        'description': 'Unrealistic salary or compensation promises'
    },
    'communication_red_flags': {
        'weight': 20,
        'keywords': [
            r"@gmail\.com",
            r"@yahoo\.com",
            r"@hotmail\.com",
            r"@outlook\.com",
            r"@aol\.com",
            r"@protonmail\.com",
            r"@mail\.com",
            r"whatsapp\s*(?:only|number)",
            r"text\s*me\s*(?:at|on)",
            r"telegram",
            r"signal\s*(?:app|messenger)",
            r"google\s*hangouts",
            r"whatsapp\s*(?:number)?.*mandatory",
            r"whatsapp\s*(?:number)?.*required",
        ],
        'description': 'Personal email or messaging apps for business communication'
    },
    'generic_addressing': {
        'weight': 10,
        'keywords': [
            r"dear\s*candidate",
            r"dear\s*applicant",
            r"dear\s*sir/?ma'am",
            r"to\s*whom\s*it\s*may\s*concern",
            r"dear\s*(?:job\s*)?seeker",
            r"hi\s*there",
        ],
        'description': 'Generic/mass-mail addressing instead of personalized'
    },
    'impersonation_patterns': {
        'weight': 20,
        'keywords': [
            r"(?:microsoft|apple|amazon|google|meta|facebook)-?careers?\.",
            r"(?:microsoft|apple|amazon|google|meta|facebook)-?jobs?\.",
            r"recruit-?[a-z]+\.(?:com|net)",
            r"hiring-?[a-z]+\.(?:com|net)",
            r"career-?[a-z]+\.(?:com|net)",
            r"job-?[a-z]+\.(?:com|net)",
        ],
        'description': 'Domain patterns that mimic legitimate companies'
    },
}
# ============================================================================
# REVISED SCORING WEIGHTS (July 26, 2026)
# Updated based on field test results:
# - Wire fraud under-weighted
# - Domain spoofing (NONE auth) undetected  
# - Gmail/Hotmail false positives too high
# ============================================================================

DOMAIN_AUTH_PENALTIES = {
    "ALL_THREE_MISSING": 25,        # SPF+DKIM+DMARC all = "none" on branded domain
    "TWO_MISSING": 10,              # Two of three missing
    "ONE_MISSING": 0,               # One missing is common, no penalty
}

DOMAIN_REPUTATION_WEIGHTS = {
    "WHOIS_NOT_FOUND": 10,          # Unknown age ≠ safe age
    "VIRUSTOTAL_NOT_IN_DB": 5,      # New/unindexed domain
    "VIRUSTOTAL_RED_FLAG": 40,      # Confirmed malicious
    "DOMAIN_AGE_DAYS_0_30": 15,     # Brand new domain
    "DOMAIN_AGE_DAYS_31_90": 10,    # Recently created
}

BRAND_IMPERSONATION_LIST = [
    "deloitte", "boeing", "centene", "mckesson", "edward_jones",
    "microsoft", "apple", "amazon", "google", "meta", "facebook",
]

SCORE_BANDS = {
    "MINIMAL": {"max": 20, "color": "#6bff6b", "label": "MINIMAL RISK"},
    "LOW": {"min": 21, "max": 40, "color": "#ffd93d", "label": "LOW RISK"},
    "MEDIUM": {"min": 41, "max": 70, "color": "#ffa500", "label": "MEDIUM RISK"},
    "HIGH": {"min": 71, "max": 100, "color": "#ff6b6b", "label": "HIGH RISK"},
}



# ============================================================================
# CONFIG MANAGEMENT
# ============================================================================

def load_config():
    """Load API keys and settings from config file."""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_config(config):
    """Save config to file with restricted permissions."""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)
    os.chmod(CONFIG_FILE, 0o600)

# ============================================================================
# EMAIL PARSING
# ============================================================================

def parse_mbox_file(filepath):
    """Parse an .mbox file and return a list of email.Message objects.
    
    Args:
        filepath: Path to .mbox file
        
    Returns:
        List of email.Message objects (one per email in the mbox)
    """
    import mailbox
    
    messages = []
    mbox = mailbox.mbox(filepath)
    
    for key in mbox.iterkeys():
        msg = mbox[key]
        messages.append(msg)
    
    mbox.close()
    return messages


def mbox_to_text_list(filepath):
    """Parse .mbox and return list of (subject, sender, raw_text) tuples.
    
    Useful for GUI display when selecting which email to analyze.
    """
    import email
    
    messages = parse_mbox_file(filepath)
    result = []
    
    for msg in messages:
        subject = msg.get('Subject', '(No Subject)')
        sender = msg.get('From', '(Unknown Sender)')
        date = msg.get('Date', '(Unknown Date)')
        raw_text = msg.as_string()
        result.append((subject, sender, date, raw_text))
    
    return result

def parse_eml_file(filepath):
    """Parse a .eml file into an email message object."""
    try:
        with open(filepath, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        return msg
    except Exception as e:
        print(f"Error parsing .eml file: {e}")
        return None

def parse_pasted_email(raw_text):
    """Parse pasted email text (headers + body) into a message object."""
    try:
        msg = Parser(policy=policy.default).parsestr(raw_text)
        return msg
    except Exception as e:
        print(f"Error parsing pasted email: {e}")
        return None

def extract_sender_domain(msg):
    """Extract the domain from the From header."""
    from_header = msg.get('From', '')
    email_match = re.search(r'<([^>]+)>', from_header)
    if email_match:
        email_addr = email_match.group(1)
    else:
        email_addr = from_header.strip()
    
    if '@' in email_addr:
        domain = email_addr.split('@')[-1].strip('>').strip()
        return domain.lower(), email_addr.lower()
    return "", email_addr

def extract_body(msg):
    """Extract the email body as plain text."""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            if content_type == "text/plain" and "attachment" not in content_disposition:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        body += payload.decode(charset, errors='replace')
                    except Exception:
                        body += payload.decode('utf-8', errors='replace')
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            try:
                body = payload.decode(charset, errors='replace')
            except Exception:
                body = payload.decode('utf-8', errors='replace')
    return body

def extract_urls(text):
    """Extract all URLs from email body or headers."""
    url_pattern = r'https?://[^\s<>"\']+'
    urls = re.findall(url_pattern, text)
    cleaned = []
    for url in urls:
        url = url.rstrip('.,;:!?)')
        if url not in cleaned:
            cleaned.append(url)
    return urls

def extract_received_ips(msg):
    """Extract sending IP addresses from Received headers."""
    received = msg.get_all('Received', [])
    if not received:
        return []
    
    ips = []
    for r in received:
        ip_matches = re.findall(r'\[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\]', str(r))
        ips.extend(ip_matches)
    return ips

def extract_headers(msg):
    """Extract all headers as a dictionary."""
    headers = {}
    for key, value in msg.items():
        if key in headers:
            if isinstance(headers[key], list):
                headers[key].append(str(value))
            else:
                headers[key] = [headers[key], str(value)]
        else:
            headers[key] = str(value)
    return headers


# ============================================================================
# AUTHENTICATION CHECKS (SPF / DKIM / DMARC)
# ============================================================================

def check_spf(msg):
    """Check SPF authentication result from headers."""
    spf_header = msg.get('Received-SPF', '')
    if spf_header:
        result = spf_header.split()[0].lower() if spf_header else 'none'
        return {'result': result, 'source': 'Received-SPF header'}
    
    auth_results = msg.get('Authentication-Results', '')
    if auth_results:
        spf_match = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
        if spf_match:
            return {'result': spf_match.group(1).lower(), 'source': 'Authentication-Results header'}
    
    # CHANGED: Return 'no_header' instead of 'none' to distinguish
    # "headers absent" from "domain has no SPF record"
    return {'result': 'no_header', 'source': 'no authentication headers found'}

def check_dkim(msg):
    """Check DKIM authentication result from headers."""
    auth_results = msg.get('Authentication-Results', '')
    if auth_results:
        dkim_match = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
        if dkim_match:
            return {'result': dkim_match.group(1).lower(), 'source': 'Authentication-Results header'}
    
    dkim_sig = msg.get('DKIM-Signature', '')
    if dkim_sig:
        return {'result': 'present', 'source': 'DKIM-Signature header (not validated)'}
    
    # CHANGED: Same as SPF
    return {'result': 'no_header', 'source': 'no authentication headers found'}

def check_dmarc(msg):
    """Check DMARC authentication result from headers."""
    auth_results = msg.get('Authentication-Results', '')
    if auth_results:
        dmarc_match = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
        if dmarc_match:
            return {'result': dmarc_match.group(1).lower(), 'source': 'Authentication-Results header'}
    
    # CHANGED: Same as SPF/DKIM
    return {'result': 'no_header', 'source': 'no authentication headers found'}

# ============================================================================
# DOMAIN REPUTATION CHECKS
# ============================================================================

def whois_domain_age(domain):
    """Check domain registration age using local whois command."""
    try:
        result = subprocess.run(
            ['whois', domain],
            capture_output=True,
            text=True,
            timeout=15
        )
        output = result.stdout.lower()
        
        date_patterns = [
            r'creation date:\s*(.+)',
            r'created:\s*(.+)',
            r'registration time:\s*(.+)',
            r'registered:\s*(.+)',
            r'domain registration date:\s*(.+)',
        ]
        
        for pattern in date_patterns:
            match = re.search(pattern, output)
            if match:
                date_str = match.group(1).strip()
                privacy_indicators = ['redacted', 'privacy', 'dataprivacy', 'proxy']
                has_privacy = any(indicator in result.stdout.lower() for indicator in privacy_indicators)
                
                return {'creation_date': date_str, 'raw_whois': result.stdout[:2000], 'privacy_protected': has_privacy}
        
        return {'creation_date': 'not found', 'raw_whois': result.stdout[:500], 'privacy_protected': False}
    
    except FileNotFoundError:
        return {'creation_date': 'error', 'raw_whois': 'whois command not installed', 'privacy_protected': False}
    except subprocess.TimeoutExpired:
        return {'creation_date': 'timeout', 'raw_whois': 'whois timed out', 'privacy_protected': False}
    except Exception as e:
        return {'creation_date': 'error', 'raw_whois': str(e), 'privacy_protected': False}

def calculate_domain_age_days(creation_date_str):
    """Attempt to parse creation date and calculate age in days."""
    date_formats = [
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S.%fZ',
        '%d-%b-%Y',
        '%Y.%m.%d',
        '%Y/%m/%d',
        '%d/%m/%Y',
        '%m/%d/%Y',
    ]
    
    for fmt in date_formats:
        try:
            created = datetime.strptime(creation_date_str.strip(), fmt)
            now = datetime.now()
            age = (now - created).days
            return age
        except ValueError:
            continue
    
    return None

def check_abuseipdb(ip_address, api_key):
    """Check IP address reputation via AbuseIPDB API."""
    if not api_key:
        return {'error': 'No AbuseIPDB API key configured'}
    
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=90"
    
    req = urllib.request.Request(url)
    req.add_header('Key', api_key)
    req.add_header('Accept', 'application/json')
    
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode())
            return data.get('data', {})
    except urllib.error.HTTPError as e:
        return {'error': f'HTTP {e.code}'}
    except Exception as e:
        return {'error': str(e)}

def check_virustotal_url(url, api_key):
    """Check a URL against VirusTotal API v3."""
    if not api_key:
        return {'error': 'No VirusTotal API key configured'}
    
    url_id = urllib.parse.quote(url, safe='')
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    req = urllib.request.Request(api_url)
    req.add_header('x-apikey', api_key)
    
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode())
            attrs = data.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {'error': 'URL not in VirusTotal database'}
        return {'error': f'HTTP {e.code}'}
    except Exception as e:
        return {'error': str(e)}

def check_virustotal_domain(domain, api_key):
    """Check a domain against VirusTotal API v3."""
    if not api_key:
        return {'error': 'No VirusTotal API key configured'}
    
    api_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    
    req = urllib.request.Request(api_url)
    req.add_header('x-apikey', api_key)
    
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode())
            attrs = data.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            reputation = attrs.get('reputation', 0)
            categories = attrs.get('categories', {})
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'reputation': reputation,
                'categories': categories,
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {'error': 'Domain not in VirusTotal database'}
        return {'error': f'HTTP {e.code}'}
    except Exception as e:
        return {'error': str(e)}

# ============================================================================
# RED FLAG CONTENT SCANNER
# ============================================================================

def scan_red_flags(text):
    """Scan email body for red flag keywords.
    
    UPDATED: Checks immediate preceding context for negation phrases
    before flagging PII/payment keywords. "No SSN needed" should not trigger.
    """
    findings = []
    text_lower = text.lower()
    
    # Categories where negation context matters
    CONTEXT_SENSITIVE_CATEGORIES = ['pii_requests', 'payment_requests']
    
    # Negation phrases — must appear within 30 chars before the keyword
    # and end right at the keyword (no other words between negation and keyword)
    # Simpler negation detection — just check if negation word appears within 
    # 40 chars before the keyword
    SIMPLE_NEGATION_WORDS = [
        r'\bno\b',
        r'\bnot\b',
        r"\bdon't\b",
        r"\bdoesn't\b",
        r"\bwon't\b",
        r'\bnever\b',
        r'\bwithout\b',
    ]
    
    for category, data in RED_FLAGS.items():
        for pattern in data['keywords']:
            matches = re.finditer(pattern, text_lower, re.IGNORECASE)
            for match in matches:
                is_negated = False
                
                if category in CONTEXT_SENSITIVE_CATEGORIES:
                    # Check 40 chars immediately before the keyword match
                    start_pos = max(0, match.start() - 40)
                    preceding_text = text_lower[start_pos:match.start()]
                    
                    # Check for any negation word in preceding text
                    for neg_word in SIMPLE_NEGATION_WORDS:
                        if re.search(neg_word, preceding_text):
                            # Additional check: keyword must be mentioned in negation context
                            # e.g., "no SSN" or "not SSN" or "no SSN needed"
                            context_check = text_lower[start_pos:match.end()]  # Include the keyword itself
                            keyword_pattern = re.escape(match.group())
                            if re.search(neg_word + r'.{0,30}' + keyword_pattern, context_check, re.IGNORECASE):
                                is_negated = True
                                break

                if not is_negated:
                    findings.append({
                        'category': category,
                        'description': data['description'],
                        'weight': data['weight'],
                        'match': match.group(),
                        'position': match.start(),
                    })
    
    # Deduplicate by (category, match)
    seen = set()
    unique = []
    for f in findings:
        key = (f['category'], f['match'])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    
    return unique
# ============================================================================
# THREAT SCORING
# ============================================================================

def calculate_threat_score(findings):
    """Calculate overall threat score from all findings.
    
    UPDATED: Missing auth now penalized more heavily.
    WHOIS "not found" treated as suspicious, not neutral.
    Free email providers penalized less unless paired with other signals.
    """
    score = 0
    reasons = []
    
    # ===========================================================================
    # 1. AUTHENTICATION PENALTIES (REVISED)
    # ===========================================================================
    auth = findings.get('authentication', {})
    
    spf = auth.get('spf', {}).get('result', 'none')
    dkim = auth.get('dkim', {}).get('result', 'none')
    dmarc = auth.get('dmarc', {}).get('result', 'none')
    
    # Count explicit failures
    failures = sum(1 for val in [spf, dkim, dmarc] if val == 'fail')
    
    # Count explicit missing (NONE) — but NOT 'no_header' (headers absent from paste)
    none_count = sum(1 for val in [spf, dkim, dmarc] if val in ['none', 'softfail'])
    
    # Track if headers were simply absent (pasted email without full headers)
    no_header_count = sum(1 for val in [spf, dkim, dmarc] if val == 'no_header')
    
    # FAIL states still penalize
    if spf == 'fail':
        score += 15
        reasons.append("SPF authentication failed")
    elif spf == 'softfail':
        score += 8
        reasons.append("SPF soft-fail")
    
    if dkim == 'fail':
        score += 15
        reasons.append("DKIM authentication failed")
    
    if dmarc == 'fail':
        score += 10
        reasons.append("DMARC check failed")
    
    # NEW: Penalty when ALL THREE are missing/none
    # But skip penalty if headers were absent (pasted email, not .eml)
    if no_header_count == 3:
        # Headers absent — can't determine auth status, don't penalize
        reasons.append("Authentication headers not present (pasted text or stripped headers)")
    elif none_count == 3:
        score += DOMAIN_AUTH_PENALTIES["ALL_THREE_MISSING"]
        reasons.append("No SPF/DKIM/DMARC authentication (highly suspicious)")
    elif none_count == 2:
        score += DOMAIN_AUTH_PENALTIES["TWO_MISSING"]
        reasons.append("Two of three authentication methods missing")
    
    # ===========================================================================
    # 2. DOMAIN AGE & WHOIS (REVISED)
    # ===========================================================================
    domain_info = findings.get('domain', {})
    domain_age = domain_info.get('age_days')
    creation_date_status = domain_info.get('creation_date_status', 'unknown')
    
    # NEW: Penalties for unknown/missing WHOIS data
    if creation_date_status == 'not found':
        score += DOMAIN_REPUTATION_WEIGHTS["WHOIS_NOT_FOUND"]
        reasons.append("Domain creation date not found (new or privacy-masked)")
    
    # Existing: Penalties for young domains (when we CAN parse)
    if domain_age is not None:
        if domain_age < 30:
            score += DOMAIN_REPUTATION_WEIGHTS["DOMAIN_AGE_DAYS_0_30"]
            reasons.append(f"Domain registered only {domain_age} days ago")
        elif domain_age < 90:
            score += DOMAIN_REPUTATION_WEIGHTS["DOMAIN_AGE_DAYS_31_90"]
            reasons.append(f"Domain registered {domain_age} days ago (relatively new)")
        elif domain_age < 365:
            score += 5
            reasons.append(f"Domain registered {domain_age} days ago")
    
    # Privacy-protected WHOIS
    if domain_info.get('privacy_protected', False):
        score += 5
        reasons.append("WHOIS privacy protection enabled")
    
    # ===========================================================================
    # 3. IP REPUTATION
    # ===========================================================================
    ip_info = findings.get('ip_reputation', {})
    if ip_info and not ip_info.get('error'):
        abuse_score = ip_info.get('abuseConfidenceScore', 0)
        if abuse_score > 50:
            score += 20
            reasons.append(f"Sender IP abuse score: {abuse_score}/100")
        elif abuse_score > 25:
            score += 10
            reasons.append(f"Sender IP abuse score: {abuse_score}/100")
    
    # ===========================================================================
    # 4. VIRUSTOTAL RESULTS (REVISED)
    # ===========================================================================
    vt_domain = findings.get('vt_domain', {})
    if vt_domain and not vt_domain.get('error'):
        malicious = vt_domain.get('malicious', 0)
        if malicious > 0:
            score += DOMAIN_REPUTATION_WEIGHTS["VIRUSTOTAL_RED_FLAG"]
            reasons.append(f"VirusTwo: {malicious} engines flagged domain as malicious")
        else:
            # Check if it's "not in database"
            if vt_domain.get('status') == 'not_in_database':
                score += DOMAIN_REPUTATION_WEIGHTS["VIRUSTOTAL_NOT_IN_DB"]
                reasons.append("Domain not in VirusTotal database (new or unindexed)")
    
    vt_urls = findings.get('vt_urls', [])
    for url_result in vt_urls:
        if not url_result.get('error'):
            malicious = url_result.get('malicious', 0)
            if malicious > 0:
                score += 15
                reasons.append(f"VirusTwo: {malicious} engines flagged URL as malicious")
    
       # ===========================================================================
    # 5. BRAND IMPERSONATION DETECTION (REVISED)
    # ===========================================================================
    sender_domain = findings.get('sender_domain', '').lower()
    
    # Official domain mappings — brand name to their actual domains
    BRAND_OFFICIAL_DOMAINS = {
        'deloitte': ['deloitte.com'],
        'boeing': ['boeing.com', 'careers.boeing.com'],
        'mckesson': ['mckesson.com'],
        'centene': ['centene.com'],
        'edward_jones': ['edwardjones.com', 'edwardsjones.com'],
        'microsoft': ['microsoft.com', 'live.com', 'outlook.com'],
        'apple': ['apple.com', 'icloud.com'],
        'amazon': ['amazon.com', 'amazon.jobs', 'amazonaws.com'],
        'google': ['google.com', 'gmail.com', 'abc.xyz'],
        'meta': ['meta.com', 'facebook.com'],
        'apple': ['apple.com'],
    }
    
    for brand, allowed_domains in BRAND_OFFICIAL_DOMAINS.items():
        # Skip if sender domain is an official domain
        if sender_domain in allowed_domains:
            continue
        
        # Check if brand name appears in sender domain but it's NOT an official domain
        # This catches "deloitte-careers.net" vs "deloitte.com"
        if brand in sender_domain:
            score += 20
            reasons.append(f"Domain resembles '{brand.title()}' but doesn't match official domain")
            break
    # ===========================================================================
    # 6. RED FLAG CONTENT (REVISED WITH FREE EMAIL EXCEPTION)
    # ===========================================================================
    red_flags = findings.get('red_flags', [])
    
    # Check if free email provider flag is present
    has_free_email_flag = any(
        f['category'] == 'communication_red_flags' and 
        f['match'] in ['@gmail.com', '@yahoo.com', '@hotmail.com', '@outlook.com']
        for f in red_flags
    )
    
    # Check if high-risk signals are present
    has_high_risk_signals = any(
        f['category'] in ['pii_requests', 'payment_requests']
        for f in red_flags
    )
    
    flag_score = 0
    for flag in red_flags:
        # Reduce free email penalty if no other suspicious signals
        if has_free_email_flag and not has_high_risk_signals:
            if flag['category'] == 'communication_red_flags':
                flag_score += 5  # Reduced from full weight
            else:
                flag_score += flag['weight']
        else:
            flag_score += flag['weight']
    
    # Cap content flags — graduated caps based on severity
    has_payment_flags = any(f['category'] == 'payment_requests' for f in red_flags)
    pii_count = sum(1 for f in red_flags if f['category'] == 'pii_requests')
    
    if has_payment_flags:
        content_cap = 70    # Payment/wire fraud = highest cap
    elif pii_count >= 3:
        content_cap = 65    # Multiple PII requests = clearly malicious
    elif pii_count >= 2:
        content_cap = 55    # Two PII types = suspicious
    else:
        content_cap = 50    # Standard cap
    
    flag_score = min(flag_score, content_cap)
    score += flag_score
    
    for flag in red_flags:
        reasons.append(f"[{flag['category']}] Found: '{flag['match']}'")
    
    # ===========================================================================
    # 7. CLAMP SCORE & DETERMINE VERDICT
    # ===========================================================================
    score = min(score, 100)
    
    # Use updated bands for verdict
    if score >= 71:
        verdict = "HIGH RISK — Likely scam"
    elif score >= 41:
        verdict = "MEDIUM RISK — Suspicious, investigate further"
    elif score >= 21:
        verdict = "LOW RISK — Some indicators present"
    else:
        verdict = "MINIMAL RISK — No significant indicators found"
    
    return {
        'score': score,
        'verdict': verdict,
        'reasons': reasons,
    }
