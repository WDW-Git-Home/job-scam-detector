"""
scam_detector_verify.py — Recruiter Identity Verification Module
Part of Job Scam Detector v3.1
"""

import whois
import dns.resolver
import requests
import re
import os
from urllib.parse import urlparse
from datetime import datetime


def whois_lookup(domain):
    """
    Look up WHOIS data for a domain.
    
    Returns:
        dict: {'created': str, 'expires': str, 'registrar': str, 'registrant': str}
    """
    try:
        w = whois.whois(domain)
        return {
            'created': getattr(w, 'creation_date', None),
            'expires': getattr(w, 'expiration_date', None),
            'registrar': getattr(w, 'registrar', None),
            'registrant': getattr(w, 'registrant', None),
            'raw': str(w)[:500]
        }
    except Exception as e:
        return {'error': str(e)}


def check_domain_age(domain):
    """
    Check how old a domain is in days.
    
    Returns:
        int: Age in days (or -1 if error)
    """
    try:
        w = whois.whois(domain)
        created = w.creation_date
        
        if created is None:
            return -1
            
        if isinstance(created, list):
            created = created[0]
        
        if isinstance(created, str):
            # Try parsing various formats
            for fmt in ['%Y-%m-%d', '%Y/%m/%d', '%d-%m-%Y']:
                try:
                    created = datetime.strptime(created[:10], fmt)
                    break
                except:
                    continue
        
        age_days = (datetime.now() - created).days
        return max(0, age_days)
    except Exception as e:
        return -1


def check_mx_records(domain):
    """
    Check if domain has valid MX records.
    
    Returns:
        dict: {'valid': bool, 'records': list}
    """
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        records = [str(r.data) for r in answers]
        return {'valid': True, 'records': records}
    except dns.resolver.NXDOMAIN:
        return {'valid': False, 'records': [], 'error': 'Domain does not exist'}
    except dns.resolver.NoAnswer:
        return {'valid': False, 'records': [], 'error': 'No MX records found'}
    except Exception as e:
        return {'valid': False, 'records': [], 'error': str(e)}


def verify_company_website(company_name, expected_domain=None):
    """
    Verify that a company's website exists and matches expected domain.
    
    Returns:
        dict: {'exists': bool, 'domain': str, 'status_code': int}
    """
    if not expected_domain:
        company_clean = company_name.lower().replace(' ', '').replace('&', '')
        candidates = [f"{company_clean}.com", f"www.{company_clean}.com"]
        expected_domain = candidates[0]
    
    url = f"https://{expected_domain}"
    
    try:
        response = requests.head(url, timeout=10, allow_redirects=True)
        return {
            'exists': response.status_code < 400,
            'domain': expected_domain,
            'status_code': response.status_code,
            'redirect_url': str(response.url) if response.history else None
        }
    except requests.exceptions.RequestException as e:
        return {'exists': False, 'domain': expected_domain, 'error': str(e)}


def check_email_pattern(email, company_domain):
    """
    Check if email follows typical corporate naming conventions.
    
    Returns:
        dict: {'matches': bool, 'pattern_detected': str, 'suspicious': bool}
    """
    username = email.split('@')[0].lower()
    
    # Common corporate patterns (safe to match)
    safe_patterns = [
        r'^[a-z]\.?([a-z]+\.)?[a-z]+$',
        r'^[a-z]+\.?[a-z]*$',
        r'^[a-z]{2,}\d+$',
    ]
    
    # Suspicious patterns
    suspicious_patterns = [
        r'^.*-jobs?.*@.*$',
        r'^.*_hr?_.*@.*$',
        r'^.*contact@.*$',
        r'^.*admin@.*$',
        r'^.*recruit.*@.*$',
        r'^.*fake.*@.*$',
    ]
    
    matches_safe = any(re.match(p, username) for p in safe_patterns)
    matches_suspicious = any(re.search(p, username) for p in suspicious_patterns)
    
    return {
        'matches': matches_safe,
        'pattern_detected': 'corporate' if matches_safe else ('suspicious' if matches_suspicious else 'unknown'),
        'suspicious': matches_suspicious
    }


def check_breach_database(email):
    """
    Check if email appears in HaveIBeenPwned breach database.
    
    Args:
        email: Email address to check
    
    Returns:
        dict: {'breached': bool, 'breaches': list}
    """
    api_key = os.environ.get('HIBP_API_KEY')
    if not api_key:
        return {'breached': False, 'note': 'No API key configured'}
    
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        'hibp-api-key': api_key,
        'user-agent': 'ScamDetector/1.0'
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            breaches = response.json()
            return {
                'breached': True,
                'breaches': [{'name': b['Name'], 'date': b['BreachDate']} for b in breaches]
            }
        elif response.status_code == 404:
            return {'breached': False, 'breaches': []}
        else:
            return {'breached': False, 'error': f'API error: {response.status_code}'}
    except Exception as e:
        return {'breached': False, 'error': str(e)}


def verify_recruiter(sender_name, sender_email, claimed_company):
    """
    Comprehensive recruiter verification.
    
    Returns:
        dict: Combined verification results with score impact
    """
    email_domain = extract_domain(sender_email)
    
    results = {}
    score_impact = 0
    flags = []
    
    # 1. WHOIS + Domain Age
    domain_age = check_domain_age(email_domain)
    results['domain_age_days'] = domain_age
    
    if domain_age < 0:
        flags.append("Domain WHOIS lookup failed")
        score_impact += 5
    elif domain_age < 30:
        flags.append(f"Domain registered only {domain_age} days ago")
        score_impact += 15
    elif domain_age < 90:
        flags.append(f"Domain registered {domain_age} days ago (relatively new)")
        score_impact += 5
    
    # 2. MX Records
    mx_result = check_mx_records(email_domain)
    results['mx_valid'] = mx_result['valid']
    results['mx_records'] = mx_result.get('records', [])
    
    if not mx_result['valid']:
        flags.append(f"No valid MX records for domain")
        score_impact += 10
    
    # 3. Company Website
    website_result = verify_company_website(claimed_company, email_domain)
    results['company_website_exists'] = website_result['exists']
    
    if not website_result['exists']:
        flags.append(f"Company website '{website_result['domain']}' not found")
        score_impact += 20
    
    # 4. Email Pattern Check
    pattern_result = check_email_pattern(sender_email, email_domain)
    results['email_pattern_matches'] = pattern_result['matches']
    results['email_pattern_suspicious'] = pattern_result['suspicious']
    
    if pattern_result['suspicious']:
        flags.append(f"Suspicious email username pattern detected")
        score_impact += 10
    
    # 5. Breach Database Check (optional)
    breach_result = check_breach_database(sender_email)
    results['in_breach_db'] = breach_result.get('breached', False)
    results['breaches'] = breach_result.get('breaches', [])
    
    if breach_result.get('breached'):
        flags.append(f"Email appears in {len(breach_result['breaches'])} breach(es)")
        score_impact += 10
    
    # Compile final result
    return {
        'verification_complete': True,
        'flags': flags,
        'score_impact': score_impact,
        **results
    }


def extract_domain(email):
    """Extract domain from email address."""
    return email.split('@')[1] if '@' in email else ''
