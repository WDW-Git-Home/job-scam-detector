"""
scam_detector_backtrace.py — Email Header Backtracing Module
Part of Job Scam Detector v3.1
"""

import re
import socket
import subprocess
import os
from urllib.parse import urlparse

try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

HIGH_RISK_COUNTRIES = {
    'NG', 'RU', 'CN', 'VN', 'PH', 'UA', 'ID', 'PK', 'BD', 'TR',
    'IR', 'KP', 'SY', 'VE', 'CU'
}

PRIVATE_IP_RANGES = [
    '10.', '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
    '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
    '172.30.', '172.31.', '192.168.', '127.', '0.'
]

def is_private_ip(ip):
    if not ip:
        return True
    for prefix in PRIVATE_IP_RANGES:
        if ip.startswith(prefix):
            return True
    return False

class EmailBacktracer:
def __init__(self, db_path=None):
        self.db_path = db_path
        self.geo_reader = None
        
        if GEOIP_AVAILABLE and db_path and os.path.exists(db_path):
            try:
                self.geo_reader = geoip2.database.Reader(db_path)
            except Exception:
                pass
    
def close(self):
        if self.geo_reader:
            self.geo_reader.close()
    
def parse_received_headers(self, raw_email):
        """Parse Received headers. Returns hops in header order (top=most recent)."""
        hops = []
        
        if '\r\n\r\n' in raw_email:
            headers_part = raw_email.split('\r\n\r\n')[0]
        elif '\n\n' in raw_email:
            headers_part = raw_email.split('\n\n')[0]
        else:
            headers_part = raw_email
        
        # Split on each "Received:" line
        lines = headers_part.split('\n')
        current_hop = None
        
        for line in lines:
            if line.strip().startswith('Received:') or \
               (line.strip().startswith('from ') and current_hop and '(' in line):
                if current_hop:
                    hops.append(current_hop)
                current_hop = {'raw': line.strip(), 'ip_address': None, 'hostname': None}
            elif current_hop and (line.strip().startswith('by ') or line.strip().startswith(';')):
                current_hop['raw'] += ' ' + line.strip()
        
        if current_hop:
            hops.append(current_hop)
        
        # Extract IPs from each hop
        for hop in hops:
            ip_pattern = r'\(((?:\d{1,3}\.){3}\d{1,3})\)|\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]'
            matches = re.findall(ip_pattern, hop['raw'])
            
            for match_group in matches:
                ip = match_group[0] or match_group[1]
                if ip:
                    hop['ip_address'] = ip
                    break
            
            hostname_pattern = r'from\s+([a-zA-Z0-9][a-zA-Z0-9\-\.]*)'
            host_match = re.search(hostname_pattern, hop['raw'], re.IGNORECASE)
            if host_match:
                hop['hostname'] = host_match.group(1)
        
        return hops
    
def extract_origin_ip(self, raw_email):
        """Extract origin IP from headers (first PUBLIC IP in chain)."""
        hops = self.parse_received_headers(raw_email)
        
        # Find first PUBLIC IP in header order (top to bottom)
        for hop in hops:
            ip = hop.get('ip_address')
            if ip and not is_private_ip(ip):
                return ip
        
        # No public IP — return first hop anyway
        if hops:
            return hops[0].get('ip_address')
        
        return None
    
def reverse_dns_lookup(self, ip_address):
        if not ip_address or is_private_ip(ip_address):
            return None
        
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            return hostname
        except Exception:
            return None
    
def geoip_lookup(self, ip_address):
        if not self.geo_reader or not ip_address or is_private_ip(ip_address):
            return None
        
        try:
            response = self.geo_reader.country(ip_address)
            return {
                'country_code': response.country.iso_code,
                'country_name': response.country.names.get('en', 'Unknown'),
                'city': response.city.names.get('en', 'Unknown'),
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'time_zone': response.location.time_zone
            }
        except Exception:
            return None
    
def asn_lookup(self, ip_address):
        if not ip_address or is_private_ip(ip_address):
            return None
        
        try:
            result = subprocess.run(['whois', '-h', 'whois.arin.net', ip_address],
                                    capture_output=True, text=True, timeout=10)
            
            asn = None
            org = None
            
            for line in result.stdout.split('\n'):
                if 'OrgName:' in line:
                    org = line.split(':', 1)[1].strip()
                if 'asn' in line.lower():
                    asn = line.split(':', 1)[1].strip()
            
            return {'org': org, 'asn': asn}
        except Exception:
            return None
    
def backtrace_email(self, raw_email):
        result = {
            'origin_ip': None,
            'origin_hostname': None,
            'reverse_dns': None,
            'geo_location': None,
            'asn_info': None,
            'total_hops': 0,
            'hops': [],
            'route_suspicious': False,
            'risk_factors': [],
            'gmail_hiding': False
        }
        
        hops = self.parse_received_headers(raw_email)
        result['total_hops'] = len(hops)
        result['hops'] = hops
        
        if not hops:
            result['risk_factors'].append("No Received: headers found")
            return result
        
        # Find first PUBLIC IP in header order (this is the true origin)
        origin_ip = None
        origin_hop = None
        
        for hop in hops:
            ip = hop.get('ip_address')
            if ip and not is_private_ip(ip):
                origin_ip = ip
                origin_hop = hop
                break
        
        # No public IP — warn user
        if not origin_ip:
            origin_ip = hops[0].get('ip_address')
            result['risk_factors'].append(f"All hops show private IPs ({origin_ip}) — origin masked")
            result['origin_ip'] = origin_ip
            return result
        
        result['origin_ip'] = origin_ip
        
        if origin_hop:
            result['origin_hostname'] = origin_hop.get('hostname')
        
        # Reverse DNS
        rdns = self.reverse_dns_lookup(origin_ip)
        result['reverse_dns'] = rdns
        
        if rdns:
            result['origin_hostname'] = rdns
        
        # GeoIP
        geo = self.geoip_lookup(origin_ip)
        result['geo_location'] = geo
        
        if geo and geo['country_code'] in HIGH_RISK_COUNTRIES:
            result['risk_factors'].append(f"Origin IP geolocated to high-risk country: {geo['country_name']} ({geo['country_code']})")
            result['route_suspicious'] = True
        
        # ASN
        asn = self.asn_lookup(origin_ip)
        result['asn_info'] = asn
        
        if asn and asn['org']:
            suspicious_orgs = ['bulletproof', 'anonymous', 'proxy', 'tor', 'vpn', 'hosting']
            if any(s in asn['org'].lower() for s in suspicious_orgs):
                result['risk_factors'].append(f"Suspicious hosting provider: {asn['org']}")
                result['route_suspicious'] = True
        
        return result
    
def _looks_like_gmail_hiding(self, raw_email):
        if 'X-Originating-IP:' in raw_email:
            return False
        
        sender_match = re.search(r'From:\s*.*<([^>]+)>', raw_email, re.IGNORECASE)
        if sender_match:
            sender_email = sender_match.group(1).lower()
            if any(provider in sender_email for provider in ['@gmail.com', '@hotmail.com', '@outlook.com', '@yahoo.com']):
                return True
        
        return False

def analyze_route_suspicion(backtrace_result, claimed_location=None):
    risk_score = 0
    findings = []
    
    geo = backtrace_result.get('geo_location')
    
    if backtrace_result.get('gmail_hiding'):
        risk_score += 5
        findings.append("Gmail/Outlook email — origin IP hidden (cannot verify location)")
    
    if claimed_location and geo:
        claimed_upper = claimed_location.upper()
        geo_country = geo.get('country_name', '').upper()
        
        if geo['country_code'] != 'US' and 'US' in claimed_upper:
            risk_score += 15
            findings.append(f"Origin: {geo['country_name']} vs Claimed: United States (MISMATCH)")
    
    if backtrace_result.get('route_suspicious'):
        risk_score += 10
        findings.extend(backtrace_result.get('risk_factors', []))
    
    return {'risk_score': risk_score, 'findings': findings, 'geo': geo}
