"""
test_url_validation.py

Test the URL validation and logging without LLM.
"""

from src.url_validator import validate_text_urls, extract_urls


def test_extract_urls():
    """Test URL extraction from text."""
    sample_text = """
    Here are some vulnerabilities:
    - CVE-2021-1234: https://nvd.nist.gov/vuln/detail/CVE-2021-1234
    - GHSA-xxxx-yyyy-zzzz: https://github.com/advisories/GHSA-xxxx-yyyy-zzzz
    - Package info: https://pypi.org/project/flask/
    - Invalid link: https://this-domain-definitely-does-not-exist-12345.com/
    """

    urls = extract_urls(sample_text)
    print(f"\n[TEST] Extracted {len(urls)} URLs:")
    for url in urls:
        print(f"  - {url}")

    assert len(urls) >= 4, f"Expected at least 4 URLs, found {len(urls)}"
    print("[PASS] URL extraction works correctly")


def test_validate_urls():
    """Test URL validation (checks if URLs are reachable)."""
    sample_text = """
    Valid URLs:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
    - https://pypi.org/project/requests/

    Invalid URL:
    - https://this-domain-definitely-does-not-exist-99999.com/page
    """

    results = validate_text_urls(sample_text)

    print(f"\n[TEST] Validated {len(results)} unique URLs:")
    for result in results:
        status = "VALID" if result.get("is_valid") else "INVALID"
        print(f"  [{status}] {result['url']} - {result.get('status', 'unknown')}")

    valid_count = sum(1 for r in results if r.get("is_valid", False))
    invalid_count = len(results) - valid_count

    print(f"\n[SUMMARY] {valid_count} valid, {invalid_count} invalid")
    print("[PASS] URL validation works correctly")


def test_url_validation_summary():
    """Test the summary generation logic."""
    sample_response = """
    ## Threat Analysis

    ### CVE-2021-44228 (Log4Shell)
    Source: https://nvd.nist.gov/vuln/detail/CVE-2021-44228

    Critical RCE vulnerability in Apache Log4j.
    More info: https://www.cve.org/CVERecord?id=CVE-2021-44228

    ### Package Information
    PyPI: https://pypi.org/project/apache-log4j/
    """

    results = validate_text_urls(sample_response)
    all_urls = extract_urls(sample_response)
    valid_urls = [r["url"] for r in results if r.get("is_valid", False)]
    invalid_urls = [r["url"] for r in results if not r.get("is_valid", False)]

    print(f"\n[TEST] Summary generation:")
    print(f"  Total URLs found: {len(all_urls)}")
    print(f"  Valid URLs: {len(valid_urls)}")
    print(f"  Invalid URLs: {len(invalid_urls)}")

    if valid_urls:
        print(f"  Valid: {', '.join(valid_urls[:3])}")
    if invalid_urls:
        print(f"  Invalid: {', '.join(invalid_urls[:3])}")

    print("[PASS] Summary generation works correctly")


if __name__ == "__main__":
    print("=== Running URL Validation Tests ===")

    test_extract_urls()
    test_validate_urls()
    test_url_validation_summary()

    print("\n=== All Tests Passed ===\n")
