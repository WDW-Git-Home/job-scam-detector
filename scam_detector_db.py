"""
scam_detector_db.py — Local Scam Database Module
Handles storage, redaction, and search of analyzed emails.
Part of Job Scam Detector v3.1
"""

import sqlite3
import hashlib
import re
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "scam_reports.db")


def init_database():
    """Initialize the local scam database."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scam_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_date TEXT NOT NULL,
            scammer_email TEXT,
            scammer_domain TEXT,
            scammer_name TEXT,
            scammer_ip TEXT,
            scammer_phone TEXT,
            threat_score INTEGER,
            risk_level TEXT,
            red_flags TEXT,
            email_subject TEXT,
            email_source TEXT,
            geo_origin TEXT,
            backtrace_hops TEXT,
            whois_created TEXT,
            mx_valid INTEGER,
            company_verified INTEGER,
            in_breach_db INTEGER,
            victim_hash TEXT,
            notes TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_scammer_email
        ON scam_reports(scammer_email)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_scammer_domain
        ON scam_reports(scammer_domain)
    """)

    conn.commit()
    conn.close()


def redact_pii(email_text):
    """Strip all recipient PII before storing."""

    # Remove recipient email addresses
    email_text = re.sub(
        r'(To|Delivered-To|X-Original-To|Return-Path):\s*[^\n]+',
        r'\1: [REDACTED]',
        email_text
    )

    # Remove email addresses that aren't the sender
    # Keep the From: line, redact everything else
    lines = email_text.split('\n')
    redacted_lines = []
    for line in lines:
        if line.strip().lower().startswith('from:'):
            redacted_lines.append(line)  # Keep sender info
        elif re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', line):
            redacted_lines.append(re.sub(
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                '[EMAIL REDACTED]',
                line
            ))
        else:
            redacted_lines.append(line)

    email_text = '\n'.join(redacted_lines)

    # Remove phone numbers (US + international)
    email_text = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE REDACTED]', email_text)
    email_text = re.sub(r'\+\d{1,3}[\s.-]?\d{1,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}', '[PHONE REDACTED]', email_text)

    # Remove SSN patterns
    email_text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[SSN REDACTED]', email_text)

    # Remove street addresses
    email_text = re.sub(
        r'\d+\s+[A-Z][a-z]+\s+(Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Blvd|Boulevard|Way|Court|Ct)',
        '[ADDRESS REDACTED]',
        email_text
    )

    # Remove recipient name from greetings
    email_text = re.sub(
        r'(Dear|Hi|Hello|Hey)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?',
        r'\1 [REDACTED]',
        email_text
    )

    return email_text


def generate_victim_hash(email_text):
    """Generate a hash of the redacted content for dedup."""
    redacted = redact_pii(email_text)
    return hashlib.sha256(redacted.encode()).hexdigest()[:16]


def store_report(report_data):
    """
    Store a scam analysis report in the database.
    
    Args:
        report_data: dict with keys matching schema columns
    
    Returns:
        int: Row ID of inserted record
    """
    init_database()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scam_reports (
            scan_date, scammer_email, scammer_domain, scammer_name,
            scammer_ip, scammer_phone, threat_score, risk_level,
            red_flags, email_subject, email_source, geo_origin,
            backtrace_hops, whois_created, mx_valid,
            company_verified, in_breach_db, victim_hash, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(),
        report_data.get('scammer_email', ''),
        report_data.get('scammer_domain', ''),
        report_data.get('scammer_name', ''),
        report_data.get('scammer_ip', ''),
        report_data.get('scammer_phone', ''),
        report_data.get('threat_score', 0),
        report_data.get('risk_level', 'Unknown'),
        report_data.get('red_flags', ''),
        report_data.get('email_subject', ''),
        report_data.get('email_source', ''),
        report_data.get('geo_origin', ''),
        report_data.get('backtrace_hops', ''),
        report_data.get('whois_created', ''),
        report_data.get('mx_valid', None),
        report_data.get('company_verified', None),
        report_data.get('in_breach_db', None),
        report_data.get('victim_hash', ''),
        report_data.get('notes', '')
    ))

    row_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return row_id


def search_reports(query_type, query_value):
    """
    Search the scam database.
    
    Args:
        query_type: 'email', 'domain', 'phone', 'name', 'subject', 'all'
        query_value: Search term
    
    Returns:
        list of dicts matching the query
    """
    init_database()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if query_type == 'email':
        cursor.execute(
            "SELECT * FROM scam_reports WHERE scammer_email LIKE ? ORDER BY scan_date DESC",
            (f'%{query_value}%',)
        )
    elif query_type == 'domain':
        cursor.execute(
            "SELECT * FROM scam_reports WHERE scammer_domain LIKE ? ORDER BY scan_date DESC",
            (f'%{query_value}%',)
        )
    elif query_type == 'phone':
        cursor.execute(
            "SELECT * FROM scam_reports WHERE scammer_phone LIKE ? ORDER BY scan_date DESC",
            (f'%{query_value}%',)
        )
    elif query_type == 'name':
        cursor.execute(
            "SELECT * FROM scam_reports WHERE scammer_name LIKE ? ORDER BY scan_date DESC",
            (f'%{query_value}%',)
        )
    elif query_type == 'subject':
        cursor.execute(
            "SELECT * FROM scam_reports WHERE email_subject LIKE ? ORDER BY scan_date DESC",
            (f'%{query_value}%',)
        )
    elif query_type == 'all':
        cursor.execute(
            "SELECT * FROM scam_reports ORDER BY scan_date DESC LIMIT 100"
        )
    else:
        conn.close()
        return []

    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return results


def check_known_scammer(email, domain):
    """
    Check if a scammer is already in the database.
    
    Returns:
        dict: {'found': bool, 'score': int, 'count': int, 'last_seen': str}
    """
    init_database()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Check by email
    cursor.execute(
        "SELECT threat_score, scan_date FROM scam_reports WHERE scammer_email = ? ORDER BY scan_date DESC",
        (email,)
    )
    email_matches = cursor.fetchall()

    # Check by domain
    cursor.execute(
        "SELECT threat_score, scan_date FROM scam_reports WHERE scammer_domain = ? ORDER BY scan_date DESC",
        (domain,)
    )
    domain_matches = cursor.fetchall()

    conn.close()

    all_matches = email_matches + domain_matches

    if not all_matches:
        return {'found': False, 'score': 0, 'count': 0, 'last_seen': ''}

    return {
        'found': True,
        'score': max(m[0] for m in all_matches),
        'count': len(all_matches),
        'last_seen': all_matches[0][1]
    }


def get_stats():
    """Return database statistics."""
    init_database()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    stats = {}

    cursor.execute("SELECT COUNT(*) FROM scam_reports")
    stats['total_reports'] = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(DISTINCT scammer_email) FROM scam_reports")
    stats['unique_emails'] = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(DISTINCT scammer_domain) FROM scam_reports")
    stats['unique_domains'] = cursor.fetchone()[0]

    cursor.execute("SELECT AVG(threat_score) FROM scam_reports")
    avg = cursor.fetchone()[0]
    stats['avg_threat_score'] = round(avg, 1) if avg else 0

    cursor.execute(
        "SELECT COUNT(*) FROM scam_reports WHERE threat_score >= 61"
    )
    stats['high_risk_count'] = cursor.fetchone()[0]

    conn.close()
    return stats


def export_database(filepath, fmt='csv'):
    """Export database contents to CSV or JSON."""
    import csv
    import json

    results = search_reports('all', '')

    if fmt == 'json':
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
    elif fmt == 'csv':
        if not results:
            return
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)

    return filepath
