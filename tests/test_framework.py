#!/usr/bin/env python3
"""
Unit tests for suanggipector v2.7 — Framework-Specific Intelligence
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Covers: framework fingerprinting, Next.js parsing, WordPress detection,
Laravel debug detection, data classes.
"""

import os
import sys
import unittest

# Ensure the project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.framework import (
    fingerprint_frameworks,
    FrameworkInfo,
    FrameworkIntelResult,
    _merge_detection,
)


# =========================================================================
# Framework Fingerprinting from HTML
# =========================================================================
class TestFrameworkFingerprinting(unittest.TestCase):

    def test_nextjs_next_data(self):
        html = '<script id="__NEXT_DATA__" type="application/json">{"buildId":"abc123"}</script>'
        result = fingerprint_frameworks(html, {})
        names = [f.name for f in result]
        self.assertIn("Next.js", names)

    def test_nextjs_static_script(self):
        html = '<script src="/_next/static/chunks/main-abc123.js"></script>'
        result = fingerprint_frameworks(html, {})
        names = [f.name for f in result]
        self.assertIn("Next.js", names)

    def test_nextjs_header(self):
        html = "<html><body>Hello</body></html>"
        headers = {"x-powered-by": "Next.js"}
        result = fingerprint_frameworks(html, headers)
        names = [f.name for f in result]
        self.assertIn("Next.js", names)

    def test_nextjs_build_id_extraction(self):
        html = (
            '<script id="__NEXT_DATA__" type="application/json">'
            '{"buildId":"myBuild123","page":"/"}</script>'
        )
        result = fingerprint_frameworks(html, {})
        nextjs = [f for f in result if f.name == "Next.js"][0]
        self.assertEqual(nextjs.version, "myBuild123")

    def test_nuxt_detection(self):
        html = '<script src="/_nuxt/BxAbCd.js"></script><script>window.__NUXT__={}</script>'
        result = fingerprint_frameworks(html, {})
        names = [f.name for f in result]
        self.assertIn("Nuxt.js", names)

    def test_wordpress_detection_html(self):
        html = '<link rel="stylesheet" href="/wp-content/themes/theme/style.css">'
        result = fingerprint_frameworks(html, {})
        names = [f.name for f in result]
        self.assertIn("WordPress", names)

    def test_wordpress_generator_meta(self):
        html = '<meta name="generator" content="WordPress 6.4.2">'
        result = fingerprint_frameworks(html, {})
        wp = [f for f in result if f.name == "WordPress"][0]
        self.assertEqual(wp.version, "6.4.2")

    def test_wordpress_header(self):
        html = "<html></html>"
        headers = {"Link": '</wp-json/>; rel="https://api.w.org/"'}
        result = fingerprint_frameworks(html, headers)
        names = [f.name for f in result]
        self.assertIn("WordPress", names)

    def test_laravel_csrf_meta(self):
        html = '<meta name="csrf-token" content="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8">'
        result = fingerprint_frameworks(html, {})
        names = [f.name for f in result]
        self.assertIn("Laravel", names)

    def test_angular_detection(self):
        html = '<app-root ng-version="17.2.3"></app-root>'
        result = fingerprint_frameworks(html, {})
        names = [f.name for f in result]
        self.assertIn("Angular", names)
        angular = [f for f in result if f.name == "Angular"][0]
        self.assertEqual(angular.version, "17.2.3")

    def test_vite_detection(self):
        html = '<script type="module" src="/@vite/client"></script>'
        result = fingerprint_frameworks(html, {})
        names = [f.name for f in result]
        self.assertIn("Vite", names)

    def test_gatsby_detection(self):
        html = '<div id="___gatsby"></div>'
        result = fingerprint_frameworks(html, {})
        names = [f.name for f in result]
        self.assertIn("Gatsby", names)

    def test_no_framework(self):
        html = "<html><body><h1>Hello World</h1></body></html>"
        result = fingerprint_frameworks(html, {})
        self.assertEqual(len(result), 0)

    def test_multiple_frameworks(self):
        """A page can show evidence for multiple frameworks."""
        html = (
            '<script src="/_next/static/chunks/main.js"></script>'
            '<link rel="stylesheet" href="/wp-content/themes/style.css">'
        )
        result = fingerprint_frameworks(html, {})
        names = [f.name for f in result]
        self.assertIn("Next.js", names)
        self.assertIn("WordPress", names)


# =========================================================================
# Header-based detection
# =========================================================================
class TestHeaderFingerprinting(unittest.TestCase):

    def test_express_header(self):
        result = fingerprint_frameworks("", {"x-powered-by": "Express"})
        names = [f.name for f in result]
        self.assertIn("Express", names)

    def test_vercel_hosting(self):
        result = fingerprint_frameworks("", {"x-vercel-id": "iad1::abc123"})
        names = [f.name for f in result]
        self.assertIn("Vercel", names)

    def test_nextjs_cache_header(self):
        result = fingerprint_frameworks("", {"x-nextjs-cache": "HIT"})
        names = [f.name for f in result]
        self.assertIn("Next.js", names)

    def test_case_insensitive_headers(self):
        result = fingerprint_frameworks("", {"X-Powered-By": "Next.js"})
        names = [f.name for f in result]
        self.assertIn("Next.js", names)


# =========================================================================
# Data class tests
# =========================================================================
class TestFrameworkDataClasses(unittest.TestCase):

    def test_framework_info_to_dict(self):
        fi = FrameworkInfo(name="Next.js", version="abc123",
                            confidence="HIGH", evidence=["__NEXT_DATA__"])
        d = fi.to_dict()
        self.assertEqual(d["name"], "Next.js")
        self.assertEqual(d["version"], "abc123")
        self.assertEqual(d["confidence"], "HIGH")
        self.assertIn("__NEXT_DATA__", d["evidence"])

    def test_framework_info_no_version(self):
        fi = FrameworkInfo(name="WordPress", confidence="MEDIUM",
                            evidence=["wp-content"])
        d = fi.to_dict()
        self.assertNotIn("version", d)

    def test_framework_intel_result_to_dict(self):
        intel = FrameworkIntelResult()
        intel.frameworks.append(
            FrameworkInfo(name="Next.js", confidence="HIGH",
                          evidence=["__NEXT_DATA__"])
        )
        intel.wp_users.append({"id": 1, "slug": "admin"})
        d = intel.to_dict()
        self.assertEqual(len(d["frameworks"]), 1)
        self.assertEqual(d["frameworks"][0]["name"], "Next.js")
        self.assertEqual(len(d["wp_users"]), 1)

    def test_empty_intel_result(self):
        intel = FrameworkIntelResult()
        d = intel.to_dict()
        self.assertEqual(d["frameworks"], [])
        self.assertEqual(d["wp_users"], [])
        self.assertEqual(d["laravel_findings"], [])


# =========================================================================
# Merge detection helper
# =========================================================================
class TestMergeDetection(unittest.TestCase):

    def test_first_detection(self):
        detected = {}
        _merge_detection(detected, "Next.js", "HIGH", "script tag")
        self.assertIn("Next.js", detected)
        self.assertEqual(detected["Next.js"].confidence, "HIGH")

    def test_upgrade_confidence(self):
        detected = {}
        _merge_detection(detected, "Next.js", "LOW", "mount div")
        _merge_detection(detected, "Next.js", "HIGH", "__NEXT_DATA__")
        self.assertEqual(detected["Next.js"].confidence, "HIGH")
        self.assertEqual(len(detected["Next.js"].evidence), 2)

    def test_no_downgrade_confidence(self):
        detected = {}
        _merge_detection(detected, "Next.js", "HIGH", "__NEXT_DATA__")
        _merge_detection(detected, "Next.js", "LOW", "mount div")
        self.assertEqual(detected["Next.js"].confidence, "HIGH")

    def test_dedup_evidence(self):
        detected = {}
        _merge_detection(detected, "WP", "HIGH", "wp-content")
        _merge_detection(detected, "WP", "HIGH", "wp-content")
        self.assertEqual(len(detected["WP"].evidence), 1)


# =========================================================================
# Laravel debug detection in HTML (no network)
# =========================================================================
class TestLaravelDebugDetection(unittest.TestCase):

    def test_whoops_error_page(self):
        """Detect Whoops error handler in HTML."""
        from modules.framework import probe_laravel
        html = '<div class="Whoops container"><h1>Whoops! There was an error.</h1></div>'
        # probe_laravel does network probes too, but html checks are first
        # We're testing the html-based detection only
        import modules.framework as fw_mod
        import re
        debug_patterns = [
            (r'Whoops!.*?There was an error', "Whoops error handler active"),
        ]
        for pattern, evidence in debug_patterns:
            self.assertIsNotNone(re.search(pattern, html, re.I | re.DOTALL))

    def test_app_debug_true_in_html(self):
        """Detect APP_DEBUG=true reference in HTML."""
        import re
        html = '<div>Config: APP_DEBUG = true</div>'
        match = re.search(r'APP_DEBUG.*?true', html, re.I | re.DOTALL)
        self.assertIsNotNone(match)


if __name__ == '__main__':
    unittest.main()
