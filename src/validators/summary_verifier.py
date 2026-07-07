"""
Summary Verification Script

Validates LLM-generated summaries against original source content by:
1. Scraping vulnerability descriptions from NVD and GitHub Advisory web pages
2. Extracting keywords using TF-IDF
3. Calculating hybrid Jaccard + fuzzy similarity scores
4. Logging results to summary_verification_logs table

Supported Sources: NVD CVE descriptions, GitHub Security Advisories

The trustability of each LLM-generated summary is calculated using a hybrid, weighted scoring system composed of two distinct metrics:
1. A Jaccard Similarity Score (weighted at 60%), which measures the exact overlap between domain-specific, TF-IDF-extracted keywords from both the LLM summary and the scraped NVD source text.
2. A Fuzzy Matching Score (weighted at 40%), which uses token set ratios to evaluate broader semantic alignment and accommodate natural phrasing variations.
These two scores are combined into a single trustability metric. If this combined score meets or exceeds a baseline threshold of 0.4 (or 0.3 for short text summaries), the summary receives a validation verdict of 'MATCH'; otherwise, it is flagged as a 'MISMATCH'.

"""

import json
import re
import time
import argparse
import logging
from typing import Dict, List, Optional

import requests
from bs4 import BeautifulSoup
from fuzzywuzzy import fuzz
from sklearn.feature_extraction.text import TfidfVectorizer
from tenacity import retry, wait_exponential, stop_after_attempt

from src.db import (
    get_db_connection,
    release_db_connection,
    get_unverified_records,
    insert_summary_verification_log,
    update_verification_status
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NVDScraper:
    """
    Web scraper for NVD vulnerability descriptions with rate limiting and retry logic.
    """

    RATE_LIMIT_DELAY = 6  # NVD compliance (6 seconds between requests)
    MAX_RETRIES = 3
    TIMEOUT = 15

    USER_AGENT = "cs-poc-data-pipeline/1.0 (Research; verification-module)"

    HEADERS = {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }

    # Fallback selectors if primary fails
    SELECTORS = [
        {'data-testid': 'vuln-description'},  # Primary
        {'class': 'vuln-detail-desc'},        # Fallback 1
        {'id': 'cveDetailDesc'}               # Fallback 2
    ]

    @retry(wait=wait_exponential(multiplier=2, min=4, max=16), stop=stop_after_attempt(3))
    def scrape_description(self, url: str) -> Dict[str, any]:
        """
        Scrape vulnerability description from NVD URL.

        Returns:
            {
                'status': 'success' | 'not_found' | 'blocked' | 'timeout' | 'error',
                'content': str | None,
                'http_status': int | None,
                'error': str | None
            }
        """
        # Rate limiting: mandatory 6-second delay
        time.sleep(self.RATE_LIMIT_DELAY)

        try:
            response = requests.get(url, headers=self.HEADERS, timeout=self.TIMEOUT)
            http_status = response.status_code

            # Handle specific error codes
            if http_status == 404:
                logger.warning(f"URL not found (404): {url}")
                return {
                    'status': 'not_found',
                    'content': None,
                    'http_status': 404,
                    'error': 'URL not found (dead link)'
                }

            if http_status == 403:
                logger.warning(f"Access blocked (403): {url}")
                return {
                    'status': 'blocked',
                    'content': None,
                    'http_status': 403,
                    'error': 'Cloudflare/WAF block detected'
                }

            response.raise_for_status()

            # Parse HTML
            soup = BeautifulSoup(response.content, 'lxml')

            # Try primary selector, then fallbacks
            desc_elem = None
            for selector in self.SELECTORS:
                desc_elem = soup.find('p', selector)
                if desc_elem:
                    break

            if not desc_elem:
                logger.error(f"Description element not found: {url}")
                # Log partial HTML for debugging
                html_snippet = str(soup)[:500] if soup else "No HTML"
                return {
                    'status': 'not_found',
                    'content': None,
                    'http_status': http_status,
                    'error': f'Description element missing. HTML snippet: {html_snippet}'
                }

            content = desc_elem.text.strip()

            if not content:
                logger.warning(f"Empty description content: {url}")
                return {
                    'status': 'not_found',
                    'content': None,
                    'http_status': http_status,
                    'error': 'Description element found but empty'
                }

            logger.info(f"Successfully scraped: {url} ({len(content)} chars)")
            return {
                'status': 'success',
                'content': content,
                'http_status': http_status,
                'error': None
            }

        except requests.exceptions.Timeout:
            logger.error(f"Timeout scraping: {url}")
            return {
                'status': 'timeout',
                'content': None,
                'http_status': None,
                'error': f'Request timeout after {self.TIMEOUT}s'
            }

        except requests.exceptions.SSLError as e:
            logger.error(f"SSL error scraping {url}: {e}")
            return {
                'status': 'error',
                'content': None,
                'http_status': None,
                'error': f'SSL certificate error: {str(e)}'
            }

        except Exception as e:
            logger.error(f"Unexpected error scraping {url}: {e}")
            return {
                'status': 'error',
                'content': None,
                'http_status': None,
                'error': f'Unexpected error: {str(e)}'
            }


class GitHubAdvisoryScraper:
    """
    Web scraper for GitHub Security Advisory descriptions with rate limiting.
    """

    RATE_LIMIT_DELAY = 2  # GitHub is more permissive than NVD
    MAX_RETRIES = 3
    TIMEOUT = 15

    USER_AGENT = "cs-poc-data-pipeline/1.0 (Research; verification-module)"

    HEADERS = {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }

    # Fallback selectors for GitHub Advisory pages
    SELECTORS = [
        {'class': 'markdown-body'},           # Primary: main content area
        {'data-view-component': 'true'},      # Fallback 1: component wrapper
        {'class': 'vulnerability-description'} # Fallback 2: specific description class
    ]

    @retry(wait=wait_exponential(multiplier=2, min=4, max=16), stop=stop_after_attempt(3))
    def scrape_description(self, url: str) -> Dict[str, any]:
        """
        Scrape vulnerability description from GitHub Advisory URL.

        Returns:
            {
                'status': 'success' | 'not_found' | 'blocked' | 'timeout' | 'error',
                'content': str | None,
                'http_status': int | None,
                'error': str | None
            }
        """
        # Rate limiting
        time.sleep(self.RATE_LIMIT_DELAY)

        try:
            response = requests.get(url, headers=self.HEADERS, timeout=self.TIMEOUT)
            http_status = response.status_code

            # Handle specific error codes
            if http_status == 404:
                logger.warning(f"URL not found (404): {url}")
                return {
                    'status': 'not_found',
                    'content': None,
                    'http_status': 404,
                    'error': 'Advisory not found (dead link)'
                }

            if http_status == 403:
                logger.warning(f"Access blocked (403): {url}")
                return {
                    'status': 'blocked',
                    'content': None,
                    'http_status': 403,
                    'error': 'GitHub rate limit or WAF block detected'
                }

            response.raise_for_status()

            # Parse HTML
            soup = BeautifulSoup(response.content, 'lxml')

            # GitHub Advisory pages have a structured layout
            # Look for the description section (typically in markdown-body class)
            desc_elem = None

            # Try to find the description in the markdown body
            markdown_sections = soup.find_all('div', {'class': 'markdown-body'})

            if markdown_sections:
                # The first significant paragraph usually contains the description
                for section in markdown_sections:
                    paragraphs = section.find_all('p')
                    if paragraphs:
                        # Combine first few paragraphs for full description
                        desc_elem = paragraphs[0]
                        break

            # Fallback to other selectors
            if not desc_elem:
                for selector in self.SELECTORS:
                    desc_elem = soup.find('p', selector)
                    if desc_elem:
                        break

            if not desc_elem:
                logger.error(f"Description element not found: {url}")
                html_snippet = str(soup)[:500] if soup else "No HTML"
                return {
                    'status': 'not_found',
                    'content': None,
                    'http_status': http_status,
                    'error': f'Description element missing. HTML snippet: {html_snippet}'
                }

            content = desc_elem.text.strip()

            if not content:
                logger.warning(f"Empty description content: {url}")
                return {
                    'status': 'not_found',
                    'content': None,
                    'http_status': http_status,
                    'error': 'Description element found but empty'
                }

            logger.info(f"Successfully scraped GitHub Advisory: {url} ({len(content)} chars)")
            return {
                'status': 'success',
                'content': content,
                'http_status': http_status,
                'error': None
            }

        except requests.exceptions.Timeout:
            logger.error(f"Timeout scraping: {url}")
            return {
                'status': 'timeout',
                'content': None,
                'http_status': None,
                'error': f'Request timeout after {self.TIMEOUT}s'
            }

        except requests.exceptions.SSLError as e:
            logger.error(f"SSL error scraping {url}: {e}")
            return {
                'status': 'error',
                'content': None,
                'http_status': None,
                'error': f'SSL certificate error: {str(e)}'
            }

        except Exception as e:
            logger.error(f"Unexpected error scraping {url}: {e}")
            return {
                'status': 'error',
                'content': None,
                'http_status': None,
                'error': f'Unexpected error: {str(e)}'
            }


class KeywordExtractor:
    """
    TF-IDF-based keyword extraction with domain-specific stopwords.
    """

    # Security domain stopwords (in addition to standard English)
    SECURITY_STOPWORDS = [
        'vulnerability', 'cve', 'issue', 'affected', 'allows', 'attacker',
        'attackers', 'exploit', 'exploited', 'attack', 'attacks', 'version',
        'versions', 'via', 'using', 'used', 'use', 'certain', 'specific'
    ]

    def __init__(self, max_features: int = 15):
        self.max_features = max_features
        self.vectorizer = TfidfVectorizer(
            max_features=max_features,
            stop_words='english',
            ngram_range=(1, 2),  # Single words + 2-word phrases
            token_pattern=r'\b[a-zA-Z]{3,}\b',  # Skip short words
            lowercase=True
        )

    def extract_keywords(self, text: str, max_keywords: int = None) -> List[str]:
        """
        Extract top keywords from text using TF-IDF.

        Args:
            text: Input text
            max_keywords: Override max_features if specified

        Returns:
            List of keyword strings
        """
        if not text or len(text.strip()) < 10:
            logger.warning("Text too short for keyword extraction")
            return []

        # Filter out security stopwords manually
        words = text.lower().split()
        filtered_text = ' '.join([w for w in words if w not in self.SECURITY_STOPWORDS])

        try:
            tfidf_matrix = self.vectorizer.fit_transform([filtered_text])
            feature_names = self.vectorizer.get_feature_names_out()

            # Get scores and sort by importance
            scores = tfidf_matrix.toarray()[0]
            keyword_scores = list(zip(feature_names, scores))
            keyword_scores.sort(key=lambda x: x[1], reverse=True)

            # Return top N keywords
            n = max_keywords if max_keywords else self.max_features
            keywords = [kw for kw, score in keyword_scores[:n] if score > 0]

            return keywords

        except Exception as e:
            logger.error(f"Error extracting keywords: {e}")
            return []


class SimilarityAnalyzer:
    """
    Hybrid similarity calculator using Jaccard + fuzzy matching.
    """

    DEFAULT_THRESHOLD = 0.4
    JACCARD_WEIGHT = 0.6
    FUZZY_WEIGHT = 0.4

    def calculate_jaccard(self, keywords_a: List[str], keywords_b: List[str]) -> float:
        """
        Calculate Jaccard similarity between two keyword lists.

        Jaccard = |A ∩ B| / |A ∪ B|
        """
        if not keywords_a or not keywords_b:
            return 0.0

        set_a = set(keywords_a)
        set_b = set(keywords_b)

        intersection = len(set_a & set_b)
        union = len(set_a | set_b)

        if union == 0:
            return 0.0

        return intersection / union

    def calculate_fuzzy(self, text_a: str, text_b: str) -> float:
        """
        Calculate fuzzy token set ratio (0.0 - 1.0).
        Handles text variations like "allows attackers" vs "enables attack".
        """
        if not text_a or not text_b:
            return 0.0

        # Truncate very long texts to avoid performance issues
        text_a = text_a[:1000]
        text_b = text_b[:1000]

        return fuzz.token_set_ratio(text_a, text_b) / 100.0

    def combined_score(
        self,
        jaccard: float,
        fuzzy: float,
        weights: tuple = None
    ) -> float:
        """
        Calculate weighted combination of Jaccard and fuzzy scores.

        Default: 0.6 * jaccard + 0.4 * fuzzy
        """
        if weights is None:
            weights = (self.JACCARD_WEIGHT, self.FUZZY_WEIGHT)

        return weights[0] * jaccard + weights[1] * fuzzy

    def get_verdict(
        self,
        combined: float,
        threshold: float = None,
        is_short: bool = False
    ) -> str:
        """
        Determine verdict based on combined score.

        Returns: 'MATCH', 'MISMATCH', or 'UNVERIFIABLE'
        """
        if threshold is None:
            threshold = self.DEFAULT_THRESHOLD

        # Lower threshold for very short summaries
        if is_short and threshold > 0.3:
            threshold = 0.3

        if combined >= threshold:
            return 'MATCH'
        else:
            return 'MISMATCH'


class VerificationOrchestrator:
    """
    Coordinates the verification workflow: query → scrape → analyze → log.
    """

    def __init__(self, source: str = 'nvd', batch_size: int = 50, verbose: bool = False):
        self.source = source
        self.batch_size = batch_size
        self.verbose = verbose

        # Initialize appropriate scraper based on source
        if source == 'github_advisories':
            self.scraper = GitHubAdvisoryScraper()
        else:  # Default to NVD
            self.scraper = NVDScraper()

        self.keyword_extractor = KeywordExtractor(max_features=15)
        self.similarity_analyzer = SimilarityAnalyzer()

        # Statistics
        self.stats = {
            'total': 0,
            'match': 0,
            'mismatch': 0,
            'unverifiable': 0,
            'errors': 0
        }

    def extract_nvd_url(self, references_json: str, canonical_id: str) -> Optional[str]:
        """
        Extract NVD URL from references_json field.
        Falls back to constructing from canonical_id if not found.
        """
        if not references_json:
            logger.warning(f"No references_json for {canonical_id}")
            return None

        try:
            urls = json.loads(references_json)

            if not urls or not isinstance(urls, list):
                logger.warning(f"Empty or invalid references_json for {canonical_id}")
                return None

            # Find NVD URL
            nvd_pattern = re.compile(r'^https://nvd\.nist\.gov/vuln/detail/')
            for url in urls:
                if nvd_pattern.match(url):
                    return url

            # Fallback: construct URL from canonical_id
            if canonical_id and canonical_id.startswith('CVE-'):
                constructed_url = f"https://nvd.nist.gov/vuln/detail/{canonical_id}"
                logger.info(f"Constructed URL for {canonical_id}: {constructed_url}")
                return constructed_url

            logger.warning(f"No NVD URL found for {canonical_id}")
            return None

        except json.JSONDecodeError as e:
            logger.error(f"Malformed JSON in references_json for {canonical_id}: {e}")
            return None

    def extract_github_advisory_url(self, references_json: str, canonical_id: str) -> Optional[str]:
        """
        Extract GitHub Advisory URL from references_json field.
        Falls back to constructing from canonical_id if not found.

        GitHub Advisory URLs follow pattern: https://github.com/advisories/GHSA-xxxx-xxxx-xxxx
        """
        if not references_json:
            logger.warning(f"No references_json for {canonical_id}")
            # Try constructing from canonical_id directly
            if canonical_id and canonical_id.startswith('GHSA-'):
                return f"https://github.com/advisories/{canonical_id}"
            return None

        try:
            urls = json.loads(references_json)

            if not urls or not isinstance(urls, list):
                logger.warning(f"Empty or invalid references_json for {canonical_id}")
                # Fallback: construct from canonical_id
                if canonical_id and canonical_id.startswith('GHSA-'):
                    constructed_url = f"https://github.com/advisories/{canonical_id}"
                    logger.info(f"Constructed URL for {canonical_id}: {constructed_url}")
                    return constructed_url
                return None

            # Find GitHub Advisory URL
            github_advisory_pattern = re.compile(r'^https://github\.com/advisories/GHSA-')
            for url in urls:
                if github_advisory_pattern.match(url):
                    return url

            # Fallback: construct URL from canonical_id
            if canonical_id and canonical_id.startswith('GHSA-'):
                constructed_url = f"https://github.com/advisories/{canonical_id}"
                logger.info(f"Constructed URL for {canonical_id}: {constructed_url}")
                return constructed_url

            logger.warning(f"No GitHub Advisory URL found for {canonical_id}")
            return None

        except json.JSONDecodeError as e:
            logger.error(f"Malformed JSON in references_json for {canonical_id}: {e}")
            return None

    def verify_record(self, record: dict) -> dict:
        """
        Verify a single threat_intelligence_records record.

        Returns log_data dict for insertion into verification_logs.
        """
        item_id = record['id']
        canonical_id = record['canonical_id']
        summary = record['summary']
        references_json = record['references_json']

        logger.info(f"Verifying {canonical_id} (id={item_id})")

        # Extract appropriate URL based on source
        if self.source == 'github_advisories':
            url = self.extract_github_advisory_url(references_json, canonical_id)
            error_msg = 'No valid GitHub Advisory URL found'
        else:  # Default to NVD
            url = self.extract_nvd_url(references_json, canonical_id)
            error_msg = 'No valid NVD URL found'

        if not url:
            return {
                'threat_intel_record_id': item_id,
                'source_url': '',
                'scrape_status': 'error',
                'scraped_content': None,
                'http_status': None,
                'keywords_llm': [],
                'keywords_source': [],
                'jaccard_score': None,
                'fuzzy_score': None,
                'combined_score': None,
                'verdict': 'UNVERIFIABLE',
                'error_msg': error_msg
            }

        # Scrape description
        scrape_result = self.scraper.scrape_description(url)

        if scrape_result['status'] != 'success':
            return {
                'threat_intel_record_id': item_id,
                'source_url': url,
                'scrape_status': scrape_result['status'],
                'scraped_content': None,
                'http_status': scrape_result.get('http_status'),
                'keywords_llm': [],
                'keywords_source': [],
                'jaccard_score': None,
                'fuzzy_score': None,
                'combined_score': None,
                'verdict': 'UNVERIFIABLE',
                'error_msg': scrape_result.get('error')
            }

        scraped_content = scrape_result['content']

        # Extract keywords
        keywords_llm = self.keyword_extractor.extract_keywords(summary, max_keywords=10)
        keywords_source = self.keyword_extractor.extract_keywords(scraped_content, max_keywords=15)

        if self.verbose:
            logger.info(f"  LLM keywords: {keywords_llm}")
            logger.info(f"  Source keywords: {keywords_source}")

        # Calculate similarity scores
        jaccard_score = self.similarity_analyzer.calculate_jaccard(keywords_llm, keywords_source)
        fuzzy_score = self.similarity_analyzer.calculate_fuzzy(summary, scraped_content)
        combined = self.similarity_analyzer.combined_score(jaccard_score, fuzzy_score)

        # Determine verdict
        is_short = len(summary) < 20
        verdict = self.similarity_analyzer.get_verdict(combined, is_short=is_short)

        if self.verbose:
            logger.info(f"  Jaccard: {jaccard_score:.3f}, Fuzzy: {fuzzy_score:.3f}, Combined: {combined:.3f}")
            logger.info(f"  Verdict: {verdict}")

        return {
            'threat_intel_record_id': item_id,
            'source_url': url,
            'scrape_status': 'success',
            'scraped_content': scraped_content,
            'http_status': scrape_result.get('http_status'),
            'keywords_llm': keywords_llm,
            'keywords_source': keywords_source,
            'jaccard_score': jaccard_score,
            'fuzzy_score': fuzzy_score,
            'combined_score': combined,
            'verdict': verdict,
            'error_msg': None
        }

    def run(self):
        """
        Main execution loop: fetch records, verify, and log results.
        """
        logger.info(f"Starting verification for source={self.source}, batch_size={self.batch_size}")

        # Get database connection
        conn = get_db_connection()
        if not conn:
            logger.error("Failed to connect to database")
            return

        try:
            # Fetch unverified records
            records = get_unverified_records(conn, self.source, self.batch_size)

            if not records:
                logger.info("No unverified records found")
                return

            logger.info(f"Found {len(records)} records to verify")
            self.stats['total'] = len(records)

            # Process each record
            for i, record in enumerate(records, 1):
                try:
                    logger.info(f"[{i}/{len(records)}] Processing {record['canonical_id']}")

                    # Verify record
                    log_data = self.verify_record(record)

                    # Insert verification log
                    insert_summary_verification_log(conn, log_data)

                    # Update threat_intelligence_records status
                    update_verification_status(conn, record['id'], log_data['verdict'])

                    # Update statistics
                    verdict = log_data['verdict']
                    if verdict == 'MATCH':
                        self.stats['match'] += 1
                    elif verdict == 'MISMATCH':
                        self.stats['mismatch'] += 1
                    else:
                        self.stats['unverifiable'] += 1

                except Exception as e:
                    logger.error(f"Error processing {record.get('canonical_id', 'unknown')}: {e}")
                    self.stats['errors'] += 1

            # Print summary
            self.print_summary()

        finally:
            release_db_connection(conn)

    def print_summary(self):
        """
        Print verification statistics.
        """
        total = self.stats['total']
        match = self.stats['match']
        mismatch = self.stats['mismatch']
        unverifiable = self.stats['unverifiable']
        errors = self.stats['errors']

        logger.info("=" * 60)
        logger.info("VERIFICATION SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Total records:   {total}")
        logger.info(f"  MATCH:         {match} ({match/total*100:.1f}%)" if total > 0 else "  MATCH:         0")
        logger.info(f"  MISMATCH:      {mismatch} ({mismatch/total*100:.1f}%)" if total > 0 else "  MISMATCH:      0")
        logger.info(f"  UNVERIFIABLE:  {unverifiable} ({unverifiable/total*100:.1f}%)" if total > 0 else "  UNVERIFIABLE:  0")
        logger.info(f"  ERRORS:        {errors}")
        logger.info("=" * 60)


def main():
    """
    CLI entry point for summary verification.
    """
    parser = argparse.ArgumentParser(
        description='Verify LLM-generated summaries against source content'
    )
    parser.add_argument(
        '--batch-size',
        type=int,
        default=50,
        help='Number of records to process (default: 50)'
    )
    parser.add_argument(
        '--source',
        type=str,
        default='nvd',
        choices=['nvd', 'github_advisories'],  # Future: pypi
        help='Source to verify (default: nvd)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Run verification
    orchestrator = VerificationOrchestrator(
        source=args.source,
        batch_size=args.batch_size,
        verbose=args.verbose
    )
    orchestrator.run()


if __name__ == '__main__':
    main()
