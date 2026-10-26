#!/usr/bin/env python3
"""
Unit tests for suanggipector v2.7
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Covers: entropy calculation, false-positive filtering, path sanitization,
AST analyzer, and regex patterns.
"""

import os
import sys
import unittest
import tempfile
import shutil

# Ensure the project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.rules import (
    REGEX_PATTERNS,
    HIGH_CONFIDENCE_TYPES,
    is_probably_noise,
    is_noise_endpoint,
    mask,
)
from core.entropy import calculate_shannon_entropy
from modules.sourcemap import _sanitize_source_path, _validate_output_path
from modules.ast_analyzer import ASTAnalyzer, ASTFinding


# =========================================================================
# Entropy tests
# =========================================================================
class TestShannonEntropy(unittest.TestCase):

    def test_empty_string(self):
        self.assertEqual(calculate_shannon_entropy(""), 0.0)

    def test_single_char(self):
        self.assertEqual(calculate_shannon_entropy("aaaa"), 0.0)

    def test_two_chars_equal(self):
        # "ab" repeated -> entropy = 1.0
        entropy = calculate_shannon_entropy("abababab")
        self.assertAlmostEqual(entropy, 1.0, places=2)

    def test_high_entropy_random(self):
        # Random-looking string should have high entropy
        entropy = calculate_shannon_entropy(
            "aK3m9Xp2Lq7Wz8Nf5Jb4Rv6Yt1Hs0Gc"
        )
        self.assertGreater(entropy, 4.0)

    def test_low_entropy_repetitive(self):
        entropy = calculate_shannon_entropy("aaaaabbbbb")
        self.assertLess(entropy, 1.5)


# Helper: build test keys at runtime so GitHub secret scanning
# does not flag literal strings in source code.
_GAPI_PREFIX = "AIza"
_GAPI_SUFFIX = "Sy" + "T3stK" + "e9Xp2Lq7Wz8Nf5Jb4Rv6Yt1Hm0Gc"  # 35 chars total


# =========================================================================
# False-positive filter tests
# =========================================================================
class TestNoiseFilters(unittest.TestCase):

    def test_webpack_noise(self):
        self.assertTrue(is_probably_noise("webpackChunkvendor"))

    def test_prototype_noise(self):
        self.assertTrue(is_probably_noise("getPrototypeOf"))

    def test_low_diversity(self):
        self.assertTrue(is_probably_noise("aaaa"))

    def test_short_hex(self):
        self.assertTrue(is_probably_noise("abcdef12"))  # < 32 chars hex

    def test_real_key_not_noise(self):
        # A realistic API key should NOT be noise
        self.assertFalse(is_probably_noise(_GAPI_PREFIX + _GAPI_SUFFIX))

    def test_noise_endpoint_css(self):
        self.assertTrue(is_noise_endpoint("style.css"))

    def test_noise_endpoint_png(self):
        self.assertTrue(is_noise_endpoint("logo.png"))

    def test_api_endpoint_not_noise(self):
        self.assertFalse(is_noise_endpoint("/api/v1/users"))

    def test_deep_path_not_noise(self):
        self.assertFalse(is_noise_endpoint("/admin/settings/security"))


# =========================================================================
# Mask utility tests
# =========================================================================
class TestMask(unittest.TestCase):

    def test_long_value(self):
        test_key = _GAPI_PREFIX + _GAPI_SUFFIX
        result = mask(test_key)
        self.assertEqual(result, test_key[:4] + "***" + test_key[-4:])

    def test_short_value(self):
        result = mask("short")
        self.assertEqual(result, "short")

    def test_exact_boundary(self):
        # len == 11 -> should mask
        result = mask("12345678901")
        self.assertEqual(result, "1234***8901")


# =========================================================================
# Source map path sanitization tests
# =========================================================================
class TestSourceMapSanitization(unittest.TestCase):

    def test_strip_webpack_prefix(self):
        result = _sanitize_source_path("webpack:///src/App.js")
        self.assertEqual(result, "src/App.js")

    def test_strip_vite_prefix(self):
        result = _sanitize_source_path("vite:///src/main.ts")
        self.assertEqual(result, "src/main.ts")

    def test_strip_traversal(self):
        result = _sanitize_source_path("../../../etc/passwd")
        self.assertEqual(result, "etc/passwd")

    def test_strip_combined(self):
        result = _sanitize_source_path("webpack:///../../../secret/key.js")
        self.assertEqual(result, "secret/key.js")

    def test_empty_after_sanitization(self):
        result = _sanitize_source_path("webpack:///")
        self.assertIsNone(result)

    def test_normal_path(self):
        result = _sanitize_source_path("src/components/Button.tsx")
        self.assertEqual(result, "src/components/Button.tsx")

    def test_validate_within_base(self):
        self.assertTrue(_validate_output_path("src/App.js", "/tmp/output"))

    def test_validate_traversal_blocked(self):
        self.assertFalse(_validate_output_path("../../etc/passwd", "/tmp/output"))


# =========================================================================
# AST Analyzer tests
# =========================================================================
class TestASTAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = ASTAnalyzer()

    def test_regex_fallback_routes(self):
        """Even without tree-sitter, regex route extraction should work."""
        js_code = '''
        const url = "/api/v1/users";
        const admin = "/admin/settings";
        const graphql = "/graphql";
        const static_asset = "/style.css";
        '''
        result = self.analyzer.analyze("test.js", js_code)
        route_values = [r.value for r in result.api_routes]
        self.assertIn("/api/v1/users", route_values)
        self.assertIn("/admin/settings", route_values)
        self.assertIn("/graphql", route_values)

    def test_regex_ignores_non_api_paths(self):
        js_code = '''
        const img = "/images/logo.png";
        '''
        result = self.analyzer.analyze("test.js", js_code)
        route_values = [r.value for r in result.api_routes]
        self.assertNotIn("/images/logo.png", route_values)

    def test_ast_finding_dataclass(self):
        f = ASTFinding(kind="fetch_call", value="/api/test", line=10, column=5)
        self.assertEqual(f.kind, "fetch_call")
        self.assertEqual(f.value, "/api/test")
        self.assertEqual(f.line, 10)

    def test_deduplication(self):
        findings = [
            ASTFinding(kind="fetch_call", value="/api/v1/test", line=1),
            ASTFinding(kind="fetch_call", value="/api/v1/test", line=5),
            ASTFinding(kind="axios_get", value="/api/v1/other", line=10),
        ]
        unique = ASTAnalyzer._deduplicate(findings)
        self.assertEqual(len(unique), 2)

    def test_ast_result_to_dict(self):
        from modules.ast_analyzer import ASTResult
        result = ASTResult(source_url="test.js")
        result.sinks.append(
            ASTFinding(kind="fetch_call", value="/api/data", line=1)
        )
        d = result.to_dict()
        self.assertEqual(d["source"], "test.js")
        self.assertEqual(len(d["sinks"]), 1)
        self.assertEqual(d["sinks"][0]["kind"], "fetch_call")


# =========================================================================
# Regex pattern tests
# =========================================================================
class TestRegexPatterns(unittest.TestCase):

    def test_google_api_key(self):
        import re
        pattern = REGEX_PATTERNS['Google API Key']
        test_key = _GAPI_PREFIX + _GAPI_SUFFIX
        match = re.search(pattern, f'key="{test_key}"')
        self.assertIsNotNone(match)

    def test_aws_access_key(self):
        import re
        pattern = REGEX_PATTERNS['Amazon AWS Access Key ID']
        match = re.search(pattern, 'AKIAIOSFODNN7EXAMPLE')
        self.assertIsNotNone(match)

    def test_github_token_classic(self):
        import re
        pattern = REGEX_PATTERNS['GitHub Token (classic)']
        match = re.search(
            pattern,
            'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234'
        )
        self.assertIsNotNone(match)

    def test_stripe_key(self):
        import re
        pattern = REGEX_PATTERNS['Stripe Key']
        match = re.search(pattern, 'sk_live_abcdefghijklmnop')
        self.assertIsNotNone(match)

    def test_jwt_pattern(self):
        import re
        pattern = REGEX_PATTERNS['JWT']
        token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
        match = re.search(pattern, token)
        self.assertIsNotNone(match)

    def test_high_confidence_coverage(self):
        """Ensure all HIGH_CONFIDENCE_TYPES exist in REGEX_PATTERNS."""
        for t in HIGH_CONFIDENCE_TYPES:
            self.assertIn(t, REGEX_PATTERNS, f"'{t}' is HIGH confidence but has no regex")


if __name__ == '__main__':
    unittest.main()
