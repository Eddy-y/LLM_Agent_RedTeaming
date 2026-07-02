"""
Test script for GitHub Advisory scraper.

Tests the GitHubAdvisoryScraper class with a known GHSA ID.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.validators.summary_verifier import GitHubAdvisoryScraper, KeywordExtractor, SimilarityAnalyzer


def test_github_scraper():
    """
    Test GitHub Advisory scraper with a known advisory.
    """
    print("=" * 80)
    print("Testing GitHub Advisory Scraper")
    print("=" * 80)

    # Known GitHub Advisory (Django vulnerability)
    test_url = "https://github.com/advisories/GHSA-2m57-hf25-phgg"
    test_ghsa_id = "GHSA-2m57-hf25-phgg"

    # Create scraper
    scraper = GitHubAdvisoryScraper()

    print(f"\nScraping: {test_url}")
    print(f"GHSA ID: {test_ghsa_id}")
    print("-" * 80)

    # Scrape description
    result = scraper.scrape_description(test_url)

    print(f"\nScrape Status: {result['status']}")
    print(f"HTTP Status: {result.get('http_status')}")

    if result['status'] == 'success':
        content = result['content']
        print(f"\nScraped Content Length: {len(content)} characters")
        print(f"\nFirst 300 chars:\n{content[:300]}...")

        # Test keyword extraction
        print("\n" + "=" * 80)
        print("Testing Keyword Extraction")
        print("=" * 80)

        extractor = KeywordExtractor(max_features=15)
        keywords = extractor.extract_keywords(content, max_keywords=10)

        print(f"\nExtracted {len(keywords)} keywords:")
        for i, kw in enumerate(keywords, 1):
            print(f"  {i}. {kw}")

        # Test with sample LLM summary
        print("\n" + "=" * 80)
        print("Testing Similarity Analysis")
        print("=" * 80)

        # Example LLM summary (you can replace this with actual summary from database)
        sample_summary = "Django vulnerability allowing unauthorized access through improper authentication"

        llm_keywords = extractor.extract_keywords(sample_summary, max_keywords=10)
        print(f"\nLLM Summary Keywords: {llm_keywords}")
        print(f"Source Keywords: {keywords}")

        analyzer = SimilarityAnalyzer()
        jaccard = analyzer.calculate_jaccard(llm_keywords, keywords)
        fuzzy = analyzer.calculate_fuzzy(sample_summary, content)
        combined = analyzer.combined_score(jaccard, fuzzy)

        print(f"\nSimilarity Scores:")
        print(f"  Jaccard: {jaccard:.3f}")
        print(f"  Fuzzy: {fuzzy:.3f}")
        print(f"  Combined: {combined:.3f}")

        verdict = analyzer.get_verdict(combined)
        print(f"\nVerdict: {verdict}")

    else:
        print(f"\nError: {result.get('error')}")
        return False

    print("\n" + "=" * 80)
    print("Test completed successfully!")
    print("=" * 80)
    return True


if __name__ == '__main__':
    try:
        success = test_github_scraper()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n[ERROR] Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
