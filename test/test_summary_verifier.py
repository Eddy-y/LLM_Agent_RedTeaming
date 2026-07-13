"""
Unit tests for summary verification components.
"""

import unittest
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.summary_verifier import KeywordExtractor, SimilarityAnalyzer


class TestKeywordExtractor(unittest.TestCase):
    """Test keyword extraction with TF-IDF."""

    def setUp(self):
        self.extractor = KeywordExtractor(max_features=10)

    def test_extract_keywords_normal_text(self):
        text = "SQL injection vulnerability in Flask 2.0 allows remote code execution via crafted payloads"
        keywords = self.extractor.extract_keywords(text)

        self.assertIsInstance(keywords, list)
        self.assertGreater(len(keywords), 0)
        # Check that some security terms are extracted
        self.assertTrue(any(kw in ['sql', 'injection', 'flask', 'remote', 'code', 'execution'] for kw in keywords))

    def test_extract_keywords_short_text(self):
        text = "Short text"
        keywords = self.extractor.extract_keywords(text)

        # Short text should still return results (even if limited)
        self.assertIsInstance(keywords, list)

    def test_extract_keywords_empty_text(self):
        text = ""
        keywords = self.extractor.extract_keywords(text)

        # Empty text should return empty list
        self.assertEqual(keywords, [])


class TestSimilarityAnalyzer(unittest.TestCase):
    """Test similarity calculation algorithms."""

    def setUp(self):
        self.analyzer = SimilarityAnalyzer()

    def test_jaccard_exact_match(self):
        keywords_a = ['sql', 'injection', 'flask']
        keywords_b = ['sql', 'injection', 'flask']

        score = self.analyzer.calculate_jaccard(keywords_a, keywords_b)
        self.assertEqual(score, 1.0)

    def test_jaccard_partial_overlap(self):
        keywords_a = ['sql', 'injection', 'flask']
        keywords_b = ['sql', 'injection', 'django', 'database']

        score = self.analyzer.calculate_jaccard(keywords_a, keywords_b)
        # 2 common / 5 total = 0.4
        self.assertAlmostEqual(score, 0.4, places=2)

    def test_jaccard_no_overlap(self):
        keywords_a = ['sql', 'injection']
        keywords_b = ['memory', 'leak']

        score = self.analyzer.calculate_jaccard(keywords_a, keywords_b)
        self.assertEqual(score, 0.0)

    def test_fuzzy_exact_match(self):
        text_a = "SQL injection in Flask 2.0"
        text_b = "SQL injection in Flask 2.0"

        score = self.analyzer.calculate_fuzzy(text_a, text_b)
        self.assertEqual(score, 1.0)

    def test_fuzzy_similar_text(self):
        text_a = "Remote code execution via debug mode"
        text_b = "Remote code execution when debug is enabled"

        score = self.analyzer.calculate_fuzzy(text_a, text_b)
        # Should be > 0.5 due to strong token overlap (remote, code, execution, debug)
        self.assertGreater(score, 0.5)

    def test_combined_score(self):
        jaccard = 0.6
        fuzzy = 0.8

        combined = self.analyzer.combined_score(jaccard, fuzzy)
        # 0.6 * 0.6 + 0.4 * 0.8 = 0.36 + 0.32 = 0.68
        self.assertAlmostEqual(combined, 0.68, places=2)

    def test_get_verdict_match(self):
        combined = 0.5
        verdict = self.analyzer.get_verdict(combined)
        self.assertEqual(verdict, 'MATCH')

    def test_get_verdict_mismatch(self):
        combined = 0.3
        verdict = self.analyzer.get_verdict(combined)
        self.assertEqual(verdict, 'MISMATCH')

    def test_get_verdict_short_summary_lower_threshold(self):
        combined = 0.35
        # Normal threshold: MISMATCH
        verdict_normal = self.analyzer.get_verdict(combined, is_short=False)
        self.assertEqual(verdict_normal, 'MISMATCH')

        # Short summary: MATCH (lower threshold)
        verdict_short = self.analyzer.get_verdict(combined, is_short=True)
        self.assertEqual(verdict_short, 'MATCH')


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling."""

    def setUp(self):
        self.extractor = KeywordExtractor()
        self.analyzer = SimilarityAnalyzer()

    def test_empty_keywords_jaccard(self):
        score = self.analyzer.calculate_jaccard([], ['sql', 'injection'])
        self.assertEqual(score, 0.0)

    def test_empty_text_fuzzy(self):
        score = self.analyzer.calculate_fuzzy("", "SQL injection")
        self.assertEqual(score, 0.0)

    def test_very_long_text_truncation(self):
        # Very long text should be handled (truncated to 1000 chars)
        long_text = "SQL injection " * 200  # ~2800 chars
        normal_text = "SQL injection in Flask"

        score = self.analyzer.calculate_fuzzy(long_text, normal_text)
        # Should still compute without error
        self.assertIsInstance(score, float)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)


if __name__ == '__main__':
    unittest.main()
