#!/usr/bin/env python3
"""
test_scam_detector.py - Regression test suite for Job Scam Detector v3.1
Run: python3 test_scam_detector.py
"""

import sys
import json
from pathlib import Path

# Ensure we can import from the project directory
sys.path.insert(0, str(Path(__file__).parent))

from scam_detector_core import calculate_threat_score


# ============================================================
# TEST CASES
# ============================================================

TEST_CASES = [
    {
        "name": "Obvious Scam - Fake Deloitte",
        "email": "hr@fake-deloitte.net",
        "domain": "fake-deloitte.net",
        "sender_name": "Sarah Mitchell",
        "company_name": "Deloitte",
        "auth": {"spf": {"result": "none"}, "dkim": {"result": "none"}, "dmarc": {"result": "none"}},
        "domain_info": {"age_days": 15, "creation_date_status": "found"},
        "expected_min_score": 75,
        "expected_verdict_contains": "CRITICAL",
        "must_contain_reason": "Deloitte",
    },
    {
        "name": "Legitimate Email - Low Risk",
        "email": "recruiting@google.com",
        "domain": "google.com",
        "sender_name": "Google Recruiting",
        "company_name": "Google",
        "auth": {"spf": {"result": "pass"}, "dkim": {"result": "pass"}, "dmarc": {"result": "pass"}},
        "domain_info": {"age_days": 9000, "creation_date_status": "found"},
        "expected_max_score": 30,
        "expected_verdict_contains": "MINIMAL",
        "must_contain_reason": None,
    },
    {
        "name": "Missing Authentication - Medium Risk",
        "email": "jobs@some-company.com",
        "domain": "some-company.com",
        "sender_name": "John Doe",
        "company_name": "Some Company",
        "auth": {"spf": {"result": "none"}, "dkim": {"result": "none"}, "dmarc": {"result": "none"}},
        "domain_info": {"age_days": 365, "creation_date_status": "found"},
        "expected_min_score": 25,
        "expected_max_score": 60,
        "expected_verdict_contains": None,
        "must_contain_reason": "SPF",
    },
]


def run_tests():
    """Run all test cases and report results."""
    passed = 0
    failed = 0
    errors = []

    print("=" * 60)
    print("Job Scam Detector v3.1 - Test Suite")
    print("=" * 60)
    print()

    for i, tc in enumerate(TEST_CASES, 1):
        print(f"[{i}/{len(TEST_CASES)}] {tc['name']}")

        try:
            findings = {
                "sender_email": tc["email"],
                "sender_domain": tc["domain"],
                "sender_name": tc["sender_name"],
                "company_name": tc["company_name"],
                "authentication": tc["auth"],
                "domain": tc["domain_info"],
                "raw_email": f"From: {tc['email']}\nSubject: Job Offer\n\nPlease review.",
                "content_lower": "please review.",
                "red_flags": [],
            }

            result = calculate_threat_score(findings)
            score = result["score"]
            verdict = result["verdict"]
            reasons = result.get("reasons", [])

            # Check minimum score
            if "expected_min_score" in tc and score < tc["expected_min_score"]:
                raise AssertionError(
                    f"Score {score} below expected minimum {tc['expected_min_score']}"
                )

            # Check maximum score
            if "expected_max_score" in tc and score > tc["expected_max_score"]:
                raise AssertionError(
                    f"Score {score} above expected maximum {tc['expected_max_score']}"
                )

            # Check verdict contains
            if tc.get("expected_verdict_contains"):
                if tc["expected_verdict_contains"].upper() not in verdict.upper():
                    raise AssertionError(
                        f"Verdict '{verdict}' does not contain '{tc['expected_verdict_contains']}'"
                    )

            # Check reason contains
            if tc.get("must_contain_reason"):
                reason_text = " ".join(reasons)
                if tc["must_contain_reason"].lower() not in reason_text.lower():
                    raise AssertionError(
                        f"Reasons do not contain '{tc['must_contain_reason']}': {reasons}"
                    )

            print(f"  PASS - Score: {score}/100")
            print(f"  Verdict: {verdict}")
            if reasons:
                print(f"  Reasons: {len(reasons)} flagged")
            print()
            passed += 1

        except Exception as e:
            print(f"  FAIL - {e}")
            print()
            failed += 1
            errors.append({"test": tc["name"], "error": str(e)})

    # Summary
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed, {len(TEST_CASES)} total")
    print("=" * 60)

    if errors:
        print("\nFailed Tests:")
        for err in errors:
            print(f"  - {err['test']}: {err['error']}")

    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
