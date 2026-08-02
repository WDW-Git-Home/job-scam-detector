#!/usr/bin/env python3
"""
scam_detector_cli.py - Command Line Interface for Job Scam Detector

Usage:
    python3 scam_detector_cli.py analyze <file.eml>          # Single file
    python3 scam_detector_cli.py batch <folder/>             # Multiple files
    python3 scam_detector_cli.py report <file.eml>           # Generate HTML report
    python3 scam_detector_cli.py --help                      # Show help
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime


def analyze_single(file_path, verbose=False):
    """Analyze a single email file."""
    from scam_detector_core import (
        parse_eml_file, parse_pasted_email, extract_sender_domain,
        check_spf, check_dkim, check_dmarc, whois_domain_age,
        calculate_domain_age_days, extract_body, scan_red_flags,
        calculate_threat_score
    )
    
    file_path = Path(file_path)
    if not file_path.exists():
        print(f"[ERROR] File not found: {file_path}")
        return False
    
    print(f"\n{'='*60}")
    print(f"Analyzing: {file_path.name}")
    print(f"{'='*60}")
    
    # Parse email
    msg = parse_eml_file(str(file_path))
    if not msg:
        # Try reading as plain text
        with open(file_path, 'r', errors='ignore') as f:
            raw = f.read()
        msg = parse_pasted_email(raw)
        if not msg:
            print("[ERROR] Failed to parse email")
            return False
    
    domain, sender_email = extract_sender_domain(msg)
    
    # Authentication checks
    spf_res = check_spf(msg)
    dkim_res = check_dkim(msg)
    dkim_res = check_dkim(msg)
    dmarc_res = check_dmarc(msg)
    
    if verbose:
        print(f"[1/6] Authentication:")
        print(f"  SPF: {spf_res.get('result', 'N/A').upper()}")
        print(f"  DKIM: {dkim_res.get('result', 'N/A').upper()}")
        print(f"  DMARC: {dmarc_res.get('result', 'N/A').upper()}")
    
    # Domain age
    domain_whois = whois_domain_age(domain) if domain else {}
    if domain_whois and domain_whois.get('creation_date') and domain_whois['creation_date'] != 'not found':
        domain_whois['age_days'] = calculate_domain_age_days(domain_whois['creation_date'])
    
    if verbose:
        print(f"\n[2/6] Domain Age:")
        if domain_whois.get('creation_date'):
            age = domain_whois.get('age_days')
            if age:
                print(f"  {age} days ({age/365:.1f} years)")
            else:
                print(f"  Creation date: {domain_whois['creation_date']}")
        else:
            print(f"  Not found / privacy protected")
    
    # Scan body
    email_body = extract_body(msg)
    red_flags = scan_red_flags(email_body)
    
    if verbose:
        print(f"\n[3/6] Red Flags:")
        if red_flags:
            categories = {}
            for rf in red_flags:
                cat = rf['category']
                categories[cat] = categories.get(cat, 0) + 1
            for cat, count in sorted(categories.items()):
                print(f"  [{cat}] {count} match(es)")
        else:
            print(f"  None detected")
    
    # Extract sender name from message
    sender_name = ''
    from_header = msg.get('From', '') if hasattr(msg, 'get') else ''
    if from_header:
        # Extract name from "Name <email>" format
        if '<' in from_header:
            sender_name = from_header.split('<')[0].strip().strip('"')
        else:
            sender_name = from_header.strip()
    
    # Extract raw email text for backtrace
    raw_email = ''
    try:
        import email
        if hasattr(msg, 'as_string'):
            raw_email = msg.as_string()
        else:
            raw_email = str(msg)
    except:
        raw_email = email_body
    
    # Try to detect company name from sender domain or email
    company_name = ''
    if sender_name:
        company_name = sender_name
    elif domain:
        company_name = domain.split('.')[0] if '.' in domain else domain
    
    # Build findings
    findings = {
        'authentication': {
            'spf': spf_res,
            'dkim': dkim_res,
            'dmarc': dmarc_res,
        },
        'domain': domain_whois,
        'red_flags': red_flags,
        'sender_email': sender_email,
        'sender_domain': domain,
        'sender_name': sender_name,
        'company_name': company_name,
        'raw_email': raw_email,
        'content_lower': email_body.lower(),
    }
    
    # Calculate threat score
    threat = calculate_threat_score(findings)
    
    # Output results

    print(f"\n{'='*60}")
    print(f"THREAT SCORE: {threat['score']}/100")
    print(f"VERDICT: {threat['verdict']}")
    print(f"{'='*60}")

    if verbose:
        # Verification status
        verified = findings.get('verified')
        if verified and verified.get('verification_complete'):
            dom_age = verified.get('domain_age_days', -1)
            mx_valid = verified.get('mx_valid', False)
            website_exists = verified.get('company_website_exists', False)
            
            dom_status = f"{dom_age} days" if dom_age > 0 else "Unknown"
            mx_status = "Valid" if mx_valid else "No MX records"
            site_status = "Exists" if website_exists else "Not found"
            
            print(f"\nRecruiter Verification:")
            print(f"  Domain Age:       {dom_status}")
            print(f"  MX Records:       {mx_status}")
            print(f"  Company Website:  {site_status}")
            
            if verified.get('flags'):
                print(f"\n  Issues Detected:")
                for flag in verified['flags']:
                    print(f"    • {flag}")
        else:
            print(f"\nRecruiter Verification: Not available")
        
        # Backtrace status
        backtrace = findings.get('backtrace')
        if backtrace:
            origin_ip = backtrace.get('origin_ip', 'N/A')
            total_hops = backtrace.get('total_hops', 0)
            geo = backtrace.get('geo_location')
            rdns = backtrace.get('reverse_dns', 'N/A')
            
            geo_str = "Unknown"
            if geo:
                geo_str = f"{geo.get('city', 'Unknown')}, {geo.get('country_name', 'Unknown')} ({geo.get('country_code', 'XX')})"
            
            print(f"\nEmail Backtrace:")
            print(f"  Origin IP:      {origin_ip}")
            print(f"  Total Hops:     {total_hops}")
            print(f"  Reverse DNS:    {rdns}")
            print(f"  Geo Location:   {geo_str}")
            
            if backtrace.get('gmail_hiding'):
                print(f"  ⚠ Gmail/Outlook email — origin IP hidden")
            
            if backtrace.get('route_suspicious'):
                print(f"\n  ⚠ Suspicious Route:")
                for factor in backtrace.get('risk_factors', []):
                    print(f"    • {factor}")
        else:
            print(f"\nEmail Backtrace: Not available")
        
        # Contributing factors
        if threat.get('reasons'):
            print(f"\nContributing Factors:")
            for reason in threat['reasons']:
                print(f"  • {reason}")
    
    print()
    return True
    return True


def analyze_batch(folder_path, verbose=False):
    """Analyze all .eml and .mbox files in a folder."""
    from scam_detector_core import (
        parse_eml_file, parse_pasted_email, extract_sender_domain,
        check_spf, check_dkim, check_dmarc, whois_domain_age,
        calculate_domain_age_days, extract_body, scan_red_flags,
        calculate_threat_score, mbox_to_text_list
    )
    
    folder = Path(folder_path)
    if not folder.exists():
        print(f"[ERROR] Folder not found: {folder}")
        return False
    
    # Collect files
    eml_files = list(folder.glob("*.eml"))
    mbox_files = list(folder.glob("*.mbox"))
    
    total_emails = len(eml_files)
    total_mboxes = len(mbox_files)
    
    # Count total emails in mboxes
    mbox_email_count = 0
    for f in mbox_files:
        try:
            emails = mbox_to_text_list(str(f))
            mbox_email_count += len(emails)
        except:
            pass
    
    total = len(eml_files) + mbox_email_count
    
    print(f"\n{'='*60}")
    print(f"BATCH ANALYSIS: {folder}")
    print(f"Found {len(eml_files)} .eml files + {len(mbox_files)} .mbox files ({total} total emails)")
    print(f"{'='*60}\n")
    
    results = []
    
    for i, eml_file in enumerate(eml_files, 1):
        success = analyze_single(eml_file, verbose=verbose)
        # Parse again for result storage (simple version)
        msg = parse_eml_file(str(eml_file)) or parse_pasted_email(eml_file.read_text(errors='ignore'))
        if msg:
            domain, sender = extract_sender_domain(msg)
            red_flags = scan_red_flags(extract_body(msg))
            threat = calculate_threat_score({
                'authentication': {'spf': check_spf(msg), 'dkim': check_dkim(msg), 'dmarc': check_dmarc(msg)},
                'domain': {},
                'red_flags': red_flags,
                'sender_email': sender,
                'sender_domain': domain,
                'content_lower': '',
            })
            results.append({
                'file': eml_file.name,
                'score': threat['score'],
                'verdict': threat['verdict']
            })
    
    # Process mboxes
    for mbox_file in mbox_files:
        try:
            emails = mbox_to_text_list(str(mbox_file))
            for j, (subject, sender, date, raw_text) in enumerate(emails):
                display_name = f"{mbox_file.name} [{j+1}] - {subject[:40]}"
                print(f"[{len(eml_files)+j+1}/{total}] {display_name}")
                
                msg = parse_pasted_email(raw_text)
                if msg:
                    domain, sender_email = extract_sender_domain(msg)
                    red_flags = scan_red_flags(extract_body(msg))
                    
                    # Quick score (skip full analysis for speed)
                    findings = {
                        'authentication': {'spf': check_spf(msg), 'dkim': check_dkim(msg), 'dmarc': check_dmarc(msg)},
                        'domain': {},
                        'red_flags': red_flags,
                        'sender_email': sender_email,
                        'sender_domain': domain,
                        'content_lower': extract_body(msg).lower(),
                    }
                    threat = calculate_threat_score(findings)
                    
                    if verbose:
                        print(f"  Score: {threat['score']}/100 - {threat['verdict']}")
                        print(f"  Score: {threat['score']}/100 - {threat['verdict']}")
                    results.append({
                        'file': display_name,
                        'score': threat['score'],
                        'verdict': threat['verdict']
                    })
        except Exception as e:
            print(f"[ERROR] {mbox_file.name}: {e}")
    
    # Summary
    print(f"\n{'='*60}")
    print(f"BATCH COMPLETE: {len(results)} emails analyzed")
    
    # Score distribution
    high_risk = sum(1 for r in results if r['score'] >= 71)
    medium_risk = sum(1 for r in results if 41 <= r['score'] < 71)
    low_risk = sum(1 for r in results if 21 <= r['score'] < 41)
    minimal_risk = sum(1 for r in results if r['score'] <= 20)
    
    print(f"HIGH RISK:   {high_risk}")
    print(f"MEDIUM RISK: {medium_risk}")
    print(f"LOW RISK:    {low_risk}")
    print(f"MINIMAL RISK: {minimal_risk}")
    print(f"{'='*60}\n")
    
    return True


def generate_report(file_path, output_path=None, format_type="html"):
    """Generate HTML report for a single email."""
    from scam_detector_core import (
        parse_eml_file, parse_pasted_email, extract_sender_domain,
        check_spf, check_dkim, check_dmarc, whois_domain_age,
        calculate_domain_age_days, extract_body, scan_red_flags,
        calculate_threat_score
    )
    from datetime import datetime
    
    file_path = Path(file_path)
    if output_path is None:
        output_path = file_path.with_suffix('.html')
    else:
        output_path = Path(output_path)
    
    # Parse and analyze
    msg = parse_eml_file(str(file_path)) or parse_pasted_email(file_path.read_text(errors='ignore'))
    if not msg:
        print(f"[ERROR] Failed to parse: {file_path}")
        return False
    
    domain, sender_email = extract_sender_domain(msg)
    spf_res = check_spf(msg)
    dkim_res = check_dkim(msg)
    dmarc_res = check_dmarc(msg)
    
    domain_whois = whois_domain_age(domain) if domain else {}
    email_body = extract_body(msg)
    red_flags = scan_red_flags(email_body)
    
    # Extract sender name and company
    sender_name = ''
    from_header = msg.get('From', '') if hasattr(msg, 'get') else ''
    if from_header:
        if '<' in from_header:
            sender_name = from_header.split('<')[0].strip().strip('"')
        else:
            sender_name = from_header.strip()
    
    company_name = sender_name or domain.split('.')[0] if domain else ''
    
    # Build findings with all required fields
    findings = {
        'authentication': {'spf': spf_res, 'dkim': dkim_res, 'dmarc': dmarc_res},
        'domain': domain_whois,
        'red_flags': red_flags,
        'sender_email': sender_email,
        'sender_domain': domain,
        'sender_name': sender_name,
        'company_name': company_name,
        'raw_email': str(msg.as_string()) if hasattr(msg, 'as_string') else str(msg),
        'content_lower': email_body.lower(),
    }
    
    threat = calculate_threat_score(findings)
    
    # Generate HTML
    color_map = {
        'HIGH RISK': '#ff6b6b',
        'MEDIUM RISK': '#ffa500',
        'LOW RISK': '#ffd93d',
        'MINIMAL RISK': '#6bff6b'
    }
    color = next((c for k, c in color_map.items() if k in threat['verdict']), '#ffffff')
    
    # Export based on format
    if format_type == "json":
        import json
        output_json = {
            "file": file_path.name,
            "timestamp": datetime.now().isoformat(),
            "score": threat['score'],
            "verdict": threat['verdict'],
            "authentication": findings['authentication'],
            "verification": findings.get('verified', {}),
            "backtrace": findings.get('backtrace', {}),
            "red_flags": red_flags,
            "contributing_factors": threat.get('reasons', [])
        }
        with open(output_path, 'w') as f:
            json.dump(output_json, f, indent=2)
        print(f"Report exported to {output_path} (JSON format)")
        return True
    
    elif format_type == "markdown":
        md_lines = [
            f"# Email Forensics Report: {file_path.name}",
            "",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Threat Assessment",
            f"- **Score:** {threat['score']}/100",
            f"- **Verdict:** {threat['verdict']}",
            "",
            "## Authentication",
            f"- SPF: {spf_res.get('result', 'N/A').upper()}",
            f"- DKIM: {dkim_res.get('result', 'N/A').upper()}",
            f"- DMARC: {dmarc_res.get('result', 'N/A').upper()}",
            "",
        ]
        
        # Verification section
        verified = findings.get('verified', {})
        if verified and verified.get('verification_complete'):
            md_lines.extend([
                "## Recruiter Verification",
                f"- Domain Age: {verified.get('domain_age_days', 'Unknown')} days",
                f"- MX Records: {'Valid' if verified.get('mx_valid') else 'No MX records'}",
                f"- Company Website: {'Exists' if verified.get('company_website_exists') else 'Not found'}",
                "",
            ])
        
        # Backtrace section
        backtrace = findings.get('backtrace', {})
        if backtrace:
            md_lines.extend([
                "## Email Backtrace",
                f"- Origin IP: {backtrace.get('origin_ip', 'N/A')}",
                f"- Total Hops: {backtrace.get('total_hops', 0)}",
                "",
            ])
        
        # Red flags
        if red_flags:
            md_lines.append("## Red Flags")
            for rf in red_flags:
                md_lines.append(f"- [{rf['category']}] {rf['match']}")
            md_lines.append("")
        
        # Contributing factors
        if threat.get('reasons'):
            md_lines.append("## Contributing Factors")
            for reason in threat['reasons']:
                md_lines.append(f"- {reason}")
            md_lines.append("")
        
        with open(output_path, 'w') as f:
            f.write('\n'.join(md_lines))
        print(f"Report exported to {output_path} (Markdown format)")
        return True
    
    else:  # HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Email Forensics Report - {file_path.name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background: #f5f5f5; }}
        .report-box {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .disclaimer {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 12px; margin: 20px 0; color: #856404; font-size: 0.9em; }}
        .score {{ font-size: 2em; font-weight: bold; color: {color}; }}
        .verdict {{ font-size: 1.2em; color: {color}; margin-bottom: 20px; }}
        .section {{ margin: 20px 0; }}
        .section-title {{ font-weight: bold; font-size: 1.1em; margin-bottom: 10px; color: #333; }}
        ul {{ margin: 5px 0; }}
        li {{ margin: 5px 0; }}
        .flag {{ background: #ffebee; padding: 8px; margin: 5px 0; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="report-box">
        <div class="disclaimer">
            <strong>⚠ DISCLAIMER:</strong> This report is generated by automated heuristic analysis and may produce false positives or false negatives.
            The threat score is an advisory indicator, not a definitive judgment. Users should conduct independent verification before acting on any findings.
        </div>
        
        <h1>🔍 Email Forensics Report</h1>
        <p><strong>File:</strong> {file_path.name}</p>
        <p><strong>Analyzed:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="section">
            <div class="score">THREAT SCORE: {threat['score']}/100</div>
            <div class="verdict">{threat['verdict']}</div>
        </div>
        
        <div class="section">
            <div class="section-title">Authentication</div>
            <ul>
                <li>SPF: {spf_res.get('result', 'N/A').upper()}</li>
                <li>DKIM: {dkim_res.get('result', 'N/A').upper()}</li>
                <li>DMARC: {dmarc_res.get('result', 'N/A').upper()}</li>
            </ul>
        </div>
        
        <div class="section">
            <div class="section-title">Contributing Factors</div>
            <ul>
"""
    
    for reason in threat.get('reasons', []):
        html += f'                <li>{reason}</li>\n'
    
    if not threat.get('reasons'):
        html += '                <li>(None)</li>\n'
    
    html += """            </ul>
        </div>
        
        <div class="section">
            <div class="section-title">Red Flags Detected</div>
"""
    
    if red_flags:
        for flag in red_flags:
            html += f'            <div class="flag">[{flag["category"]}] "{flag["match"]}" (weight: {flag["weight"]})</div>\n'
    else:
        html += '            <p>No red flags detected.</p>\n'
    
    html += f"""        </div>
    </div>
</body>
</html>
"""
    
    output_path.write_text(html)
    print(f"[SUCCESS] Report saved to: {output_path}")
    return True



def generate_reply(template_id, from_email=None, domain=None, subject=None):
    """Generate professional reply draft."""
    # Extract name/email info
    sender_name = "Recruiter"
    company_name = "[Company Name]"
    position_title = "[Position Title]"
    
    if from_email and '@' in from_email:
        sender_name = from_email.split('@')[0].replace('.', ' ').title()
    
    if domain and domain not in ['gmail.com', 'hotmail.com', 'yahoo.com']:
        company_name = domain.split('.')[0].title()
    
    if subject:
        position_title = subject.replace('Re:', '').strip()
    
    # Templates
    templates = {
        1: f"""Subject: Re: {position_title}

Dear {sender_name},

Thank you for reaching out regarding the {position_title} opportunity at {company_name}. After reviewing your message carefully, I've determined that this position does not align with my current career objectives.

I appreciate you considering me for this role. I wish you success in finding the right candidate.

Best regards,
[Your Name]
[Contact Information]""",
        
        2: f"""Subject: Re: {position_title} - Verification Request

Dear {sender_name},

Thank you for contacting me about the {position_title} role. Before proceeding, I require clarification on several points:

1. Could you provide a link to the official job posting on {company_name}'s careers page?
2. What is the direct company email domain for your organization?
3. May I confirm your full name and title via LinkedIn?

I follow standard cybersecurity practices and verify all recruiter credentials before sharing personal information.

Looking forward to your response.

Best regards,
[Your Name]""",
        
        3: f"""Subject: Re: {position_title} - Interest and Next Steps

Dear {sender_name},

Thank you for reaching out about the {position_title} opportunity at {company_name}. I'm interested in learning more.

Before scheduling, could you confirm:
- Specific requirements and qualifications sought?
- Team structure and reporting line?
- Full-time or contract position?

Looking forward to discussing alignment with my background.

Best regards,
[Your Name]
[LinkedIn URL]""",
        
        4: f"""Subject: Re: {position_title} - Unsolicited Communication

Dear {sender_name},

I've received your message regarding a job opportunity that does not match legitimate recruitment practices. Indicators suggesting potential fraud include suspicious domain, PII request, or unusual communication channel.

I will not be providing personal information. Your communication has been reported to the relevant platform.

Please remove my contact information from your database.

Regards,
[Your Name]"""
    }
    
    draft = templates.get(template_id, "Invalid template ID")
    print("\n" + "="*60)
    print("PROFESSIONAL REPLY DRAFT")
    print("="*60 + "\n")
    print(draft)
    print("\n" + "="*60)
    print("⚠️ REVIEW BEFORE SENDING!")
    print("⚠️ DO NOT SHARE PERSONAL INFO UNTIL VERIFIED!")
    print("="*60 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description='Job Scam Detector - Command Line Interface',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scam_detector_cli.py analyze job-offer.eml
  python3 scam_detector_cli.py analyze job-offer.eml --verbose
  python3 scam_detector_cli.py batch ~/Downloads/recruiter-emails/
  python3 scam_detector_cli.py report job-offer.eml --output report.html
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze single email file')
    analyze_parser.add_argument('file', type=str, help='Path to .eml or pasted email file')
    analyze_parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed analysis')
    
    # Batch command
    batch_parser = subparsers.add_parser('batch', help='Batch analyze folder of emails')
    batch_parser.add_argument('folder', type=str, help='Path to folder containing .eml/.mbox files')
    batch_parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed analysis')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate report')
    report_parser.add_argument('file', type=str, help='Path to .eml file')
    report_parser.add_argument('-o', '--output', type=str, help='Output file path')
    report_parser.add_argument('-f', '--format', choices=['html', 'json', 'markdown'], default='html',
                                help='Output format (default: html)')
    
    args = parser.parse_args()
    
    if args.command == 'report':
        success = generate_report(args.file, args.output, args.format)
        sys.exit(0 if success else 1)
    
    if args.command == 'analyze':
        success = analyze_single(args.file, verbose=args.verbose)
        sys.exit(0 if success else 1)
    elif args.command == 'batch':
        success = analyze_batch(args.folder, verbose=args.verbose)
        sys.exit(0 if success else 1)
    elif args.command == 'report':
        success = generate_report(args.file, output_path=args.output)
        sys.exit(0 if success else 1)
    elif args.command == 'reply':
        generate_reply(args.template, from_email=args.from_email, 
                      domain=args.domain, subject=args.subject)
        sys.exit(0)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
