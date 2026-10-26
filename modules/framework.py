#!/usr/bin/env python3
"""
suanggipector.modules.framework
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Framework-Specific Intelligence — v2.7

Fingerprint the target's frontend/backend framework and run
framework-specific recon:
  • Next.js  → _next/data build-ID discovery, API route probing
  • Nuxt.js  → _nuxt manifest, payload extraction
  • WordPress → REST API user enum, plugin enum, debug endpoints
  • Laravel  → Debug mode detection, .env exposure, Telescope/Ignition
  • Vite     → @vite manifest, HMR client detection
  • Webpack  → Chunk manifest, runtime globals
  • Laravel Mix → mix-manifest.json
  • React (CRA) → static/js manifest, precache-manifest
  • Angular  → ngsw.json, runtime.js
  • Vue CLI  → precache-manifest, app chunk naming

All network calls use core.crawler.request_with_retry for
consistent UA rotation, retry + backoff, and WAF resilience.
"""

import re
import json
import threading
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

from colorama import Fore

from core.crawler import request_with_retry

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FrameworkInfo:
    """Holds detection results for a single framework."""
    name: str
    version: Optional[str] = None
    confidence: str = "HIGH"  # HIGH / MEDIUM / LOW
    evidence: list = field(default_factory=list)

    def to_dict(self):
        d = {"name": self.name, "confidence": self.confidence, "evidence": self.evidence}
        if self.version:
            d["version"] = self.version
        return d


@dataclass
class FrameworkIntelResult:
    """Aggregated framework intelligence for the target."""
    frameworks: list = field(default_factory=list)          # list[FrameworkInfo]
    nextjs_data_routes: list = field(default_factory=list)  # list[dict]
    wp_users: list = field(default_factory=list)            # list[dict]
    wp_endpoints: list = field(default_factory=list)        # list[dict]
    laravel_findings: list = field(default_factory=list)    # list[dict]
    extra_js_urls: list = field(default_factory=list)       # extra JS discovered

    def to_dict(self):
        return {
            "frameworks": [f.to_dict() for f in self.frameworks],
            "nextjs_data_routes": self.nextjs_data_routes,
            "wp_users": self.wp_users,
            "wp_endpoints": self.wp_endpoints,
            "laravel_findings": self.laravel_findings,
            "extra_js_urls": self.extra_js_urls,
        }


# ---------------------------------------------------------------------------
# HTML / header fingerprinting patterns
# ---------------------------------------------------------------------------

# Patterns checked against the HTML body
_HTML_FINGERPRINTS = [
    # (name, regex, confidence, evidence_label)
    ("Next.js",    re.compile(r'<script[^>]+src="/_next/static/[^"]+\.js"', re.I),
     "HIGH", "/_next/static/ script tag"),
    ("Next.js",    re.compile(r'__NEXT_DATA__', re.I),
     "HIGH", "__NEXT_DATA__ global"),
    ("Next.js",    re.compile(r'/_next/data/[A-Za-z0-9_-]+/', re.I),
     "HIGH", "/_next/data/ endpoint reference"),
    ("Nuxt.js",    re.compile(r'<script[^>]+src="/_nuxt/[^"]+\.js"', re.I),
     "HIGH", "/_nuxt/ script tag"),
    ("Nuxt.js",    re.compile(r'__NUXT__', re.I),
     "HIGH", "__NUXT__ global"),
    ("Nuxt.js",    re.compile(r'window\.__NUXT_', re.I),
     "MEDIUM", "window.__NUXT_ global"),
    ("Vue.js",     re.compile(r'<div\s+id="app"[^>]*></div>\s*<script', re.I),
     "LOW", "Vue-style #app mount + script"),
    ("Angular",    re.compile(r'<app-root[^>]*>', re.I),
     "HIGH", "<app-root> component"),
    ("Angular",    re.compile(r'ng-version="', re.I),
     "HIGH", "ng-version attribute"),
    ("React",      re.compile(r'<div\s+id="root"[^>]*></div>', re.I),
     "LOW", "React-style #root mount"),
    ("React",      re.compile(r'react\.production\.min\.js|react-dom\.production', re.I),
     "HIGH", "React production bundle reference"),
    ("Vite",       re.compile(r'<script[^>]+type="module"[^>]+src="/@vite', re.I),
     "HIGH", "Vite dev client script"),
    ("Vite",       re.compile(r'/@vite/client', re.I),
     "HIGH", "Vite HMR client reference"),
    ("WordPress",  re.compile(r'/wp-content/', re.I),
     "HIGH", "/wp-content/ path"),
    ("WordPress",  re.compile(r'/wp-includes/', re.I),
     "HIGH", "/wp-includes/ path"),
    ("WordPress",  re.compile(r'<meta[^>]+name="generator"[^>]+content="WordPress', re.I),
     "HIGH", "WordPress generator meta"),
    ("Laravel",    re.compile(r'<meta[^>]+name="csrf-token"[^>]+content="[^"]{30,}"', re.I),
     "MEDIUM", "CSRF token meta (Laravel-style)"),
    ("Laravel Mix", re.compile(r'/js/app\.js\?id=', re.I),
     "MEDIUM", "Laravel Mix versioned asset"),
    ("Gatsby",     re.compile(r'___gatsby', re.I),
     "HIGH", "Gatsby root div"),
    ("Svelte",     re.compile(r'__svelte', re.I),
     "MEDIUM", "Svelte hydration marker"),
]

# Patterns checked against HTTP response headers
_HEADER_FINGERPRINTS = [
    # (name, header_name_lower, value_regex, confidence, evidence_label)
    ("Next.js",    "x-powered-by",   re.compile(r'Next\.js', re.I),
     "HIGH", "x-powered-by: Next.js header"),
    ("Express",    "x-powered-by",   re.compile(r'Express', re.I),
     "MEDIUM", "x-powered-by: Express header"),
    ("WordPress",  "x-powered-by",   re.compile(r'WordPress', re.I),
     "HIGH", "x-powered-by: WordPress header"),
    ("Laravel",    "x-powered-by",   re.compile(r'Laravel', re.I),
     "HIGH", "x-powered-by: Laravel header"),
    ("PHP",        "x-powered-by",   re.compile(r'PHP/', re.I),
     "MEDIUM", "x-powered-by: PHP header"),
    ("WordPress",  "link",           re.compile(r'wp-json', re.I),
     "HIGH", "Link header references wp-json"),
    ("Next.js",    "x-nextjs-cache", re.compile(r'.+'),
     "HIGH", "x-nextjs-cache header present"),
    ("Vercel",     "x-vercel-id",    re.compile(r'.+'),
     "MEDIUM", "x-vercel-id header (Vercel hosting)"),
    ("Netlify",    "x-nf-request-id", re.compile(r'.+'),
     "MEDIUM", "x-nf-request-id header (Netlify hosting)"),
]

# ---------------------------------------------------------------------------
# Probe paths — framework-specific URLs to check
# ---------------------------------------------------------------------------

# Next.js probes
_NEXTJS_WELL_KNOWN = [
    "/_next/data/{buildId}/index.json",
    "/api",
    "/api/auth/session",
    "/api/auth/providers",
    "/api/auth/csrf",
]

# WordPress probes
_WP_PROBE_PATHS = [
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/posts?per_page=5",
    "/wp-json/wp/v2/categories",
    "/wp-json/wp/v2/tags",
    "/wp-json/",
    "/wp-json/wp/v2/plugins",
    "/?rest_route=/wp/v2/users",         # Fallback if pretty permalinks off
    "/xmlrpc.php",
    "/wp-login.php",
    "/readme.html",
]

# Laravel probes
_LARAVEL_PROBE_PATHS = [
    "/.env",
    "/_ignition/health-check",
    "/_ignition/execute-solution",
    "/telescope",
    "/telescope/requests",
    "/horizon",
    "/horizon/api/stats",
    "/api",
    "/storage/logs/laravel.log",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",  # Common misconfig
]


# ---------------------------------------------------------------------------
# Fingerprinting engine
# ---------------------------------------------------------------------------

def fingerprint_frameworks(html_content: str, headers: dict) -> list:
    """
    Detect frameworks from HTML content and HTTP headers.
    Returns list of FrameworkInfo, deduplicated by name (highest confidence wins).
    """
    detected = {}  # name -> FrameworkInfo

    # Check HTML body patterns
    for name, pattern, confidence, evidence_label in _HTML_FINGERPRINTS:
        if pattern.search(html_content):
            _merge_detection(detected, name, confidence, evidence_label)

    # Check HTTP headers
    headers_lower = {k.lower(): v for k, v in headers.items()}
    for name, header_name, value_pattern, confidence, evidence_label in _HEADER_FINGERPRINTS:
        header_val = headers_lower.get(header_name, "")
        if header_val and value_pattern.search(header_val):
            _merge_detection(detected, name, confidence, evidence_label)

    # Extract Next.js version from __NEXT_DATA__
    if "Next.js" in detected:
        version_match = re.search(
            r'"nextExport"\s*:\s*\w+.*?"buildId"\s*:\s*"([^"]+)"', html_content
        )
        if not version_match:
            version_match = re.search(r'"buildId"\s*:\s*"([^"]+)"', html_content)
        if version_match:
            detected["Next.js"].version = version_match.group(1)

    # Extract WordPress version
    if "WordPress" in detected:
        wp_ver = re.search(
            r'<meta[^>]+content="WordPress\s+([\d.]+)"', html_content, re.I
        )
        if wp_ver:
            detected["WordPress"].version = wp_ver.group(1)

    # Extract Angular version
    if "Angular" in detected:
        ng_ver = re.search(r'ng-version="([\d.]+)"', html_content)
        if ng_ver:
            detected["Angular"].version = ng_ver.group(1)

    return list(detected.values())


def _merge_detection(detected: dict, name: str, confidence: str, evidence: str):
    """Merge a detection into the dict, keeping highest confidence."""
    conf_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    if name not in detected:
        detected[name] = FrameworkInfo(
            name=name, confidence=confidence, evidence=[evidence]
        )
    else:
        existing = detected[name]
        if evidence not in existing.evidence:
            existing.evidence.append(evidence)
        if conf_rank.get(confidence, 0) > conf_rank.get(existing.confidence, 0):
            existing.confidence = confidence


# ---------------------------------------------------------------------------
# Next.js specific intelligence
# ---------------------------------------------------------------------------

def probe_nextjs(target_url: str, html_content: str, build_id: str = None):
    """
    Next.js specific recon:
    - Extract buildId from __NEXT_DATA__
    - Probe _next/data/{buildId}/index.json
    - Discover API routes from __NEXT_DATA__ and page props
    - Check common Next.js API routes (/api/auth/...)
    """
    findings = {
        "build_id": None,
        "data_routes": [],
        "api_routes": [],
        "page_props_keys": [],
    }

    # Extract buildId
    if not build_id:
        bid_match = re.search(r'"buildId"\s*:\s*"([^"]+)"', html_content)
        if bid_match:
            build_id = bid_match.group(1)

    if not build_id:
        print(Fore.YELLOW + "[FRAMEWORK] Next.js detected but buildId not found in HTML.")
        return findings

    findings["build_id"] = build_id
    print(Fore.CYAN + f"[FRAMEWORK] Next.js buildId: {build_id}")

    # Extract pages from __NEXT_DATA__
    next_data_match = re.search(
        r'<script[^>]*id="__NEXT_DATA__"[^>]*>(.*?)</script>',
        html_content, re.DOTALL
    )
    if next_data_match:
        try:
            next_data = json.loads(next_data_match.group(1))
            # Extract page path
            page = next_data.get("page", "/")
            findings["data_routes"].append({
                "page": page,
                "data_url": f"/_next/data/{build_id}{page}.json"
                            if page != "/" else f"/_next/data/{build_id}/index.json",
            })
            # Extract pageProps keys for intel
            props = next_data.get("props", {}).get("pageProps", {})
            if props:
                findings["page_props_keys"] = list(props.keys())[:20]

            # Dynamic routes from buildManifest if available
            if "buildManifest" in next_data:
                manifest = next_data["buildManifest"]
                for route_path in manifest.get("sortedPages", []):
                    if route_path.startswith("/api/"):
                        findings["api_routes"].append(route_path)

        except (json.JSONDecodeError, KeyError):
            pass

    # Probe _next/data endpoint
    base = target_url.rstrip("/")
    data_url = f"{base}/_next/data/{build_id}/index.json"
    try:
        resp = request_with_retry(data_url, timeout=8, retries=2,
                                   base_delay=0.5, rotate_ua=True)
        if resp.status_code == 200:
            print(Fore.GREEN + f"  [NEXT.JS] _next/data accessible: {data_url}")
            findings["data_routes"].append({
                "page": "/",
                "data_url": data_url,
                "status": resp.status_code,
                "size": len(resp.text),
            })
            # Try to extract data keys
            try:
                data_json = resp.json()
                page_props = data_json.get("pageProps", {})
                if page_props:
                    print(Fore.WHITE + f"    |__ pageProps keys: {list(page_props.keys())[:10]}")
            except json.JSONDecodeError:
                pass
        elif resp.status_code == 404:
            print(Fore.YELLOW + f"  [NEXT.JS] _next/data returned 404 (SSG not used for index)")
    except Exception:
        pass

    # Check common Next.js API routes
    common_api = ["/api", "/api/auth/session", "/api/auth/providers",
                  "/api/auth/csrf", "/api/health", "/api/config"]
    for route in common_api:
        try:
            url = base + route
            resp = request_with_retry(url, timeout=6, retries=1,
                                       base_delay=0.5, rotate_ua=True)
            if resp.status_code < 404:
                findings["api_routes"].append(route)
                print(Fore.GREEN + f"  [NEXT.JS] API route found: {route} -> {resp.status_code}")
        except Exception:
            continue

    return findings


# ---------------------------------------------------------------------------
# WordPress specific intelligence
# ---------------------------------------------------------------------------

def probe_wordpress(target_url: str):
    """
    WordPress specific recon:
    - Enumerate users via /wp-json/wp/v2/users
    - Check plugin/theme exposure
    - Probe wp-login, xmlrpc, readme
    - REST API namespace discovery
    """
    findings = {
        "users": [],
        "rest_endpoints": [],
        "exposed_paths": [],
        "namespaces": [],
    }

    base = target_url.rstrip("/")

    # REST API namespace discovery
    try:
        resp = request_with_retry(f"{base}/wp-json/", timeout=8, retries=2,
                                   base_delay=0.5, rotate_ua=True)
        if resp.status_code == 200:
            try:
                api_data = resp.json()
                namespaces = api_data.get("namespaces", [])
                findings["namespaces"] = namespaces
                if namespaces:
                    print(Fore.GREEN + f"  [WP] REST API namespaces: {namespaces[:10]}")
                # Site info
                name = api_data.get("name", "")
                desc = api_data.get("description", "")
                if name:
                    print(Fore.WHITE + f"    |__ Site name: {name}")
                    findings["rest_endpoints"].append({
                        "path": "/wp-json/",
                        "status": 200,
                        "site_name": name,
                        "site_description": desc,
                    })
            except json.JSONDecodeError:
                findings["rest_endpoints"].append({
                    "path": "/wp-json/", "status": 200, "note": "non-JSON response"
                })
    except Exception:
        pass

    # User enumeration
    user_urls = [
        f"{base}/wp-json/wp/v2/users",
        f"{base}/?rest_route=/wp/v2/users",
    ]
    for user_url in user_urls:
        try:
            resp = request_with_retry(user_url, timeout=8, retries=2,
                                       base_delay=0.5, rotate_ua=True)
            if resp.status_code == 200:
                try:
                    users = resp.json()
                    if isinstance(users, list):
                        for u in users[:20]:
                            user_info = {
                                "id": u.get("id"),
                                "name": u.get("name", ""),
                                "slug": u.get("slug", ""),
                                "description": u.get("description", "")[:100],
                            }
                            findings["users"].append(user_info)
                            print(Fore.RED +
                                  f"  [WP] User exposed: {user_info['slug']} "
                                  f"(id={user_info['id']}, name={user_info['name']})")
                        break  # Got users, no need to try fallback
                except json.JSONDecodeError:
                    pass
            elif resp.status_code == 401:
                print(Fore.YELLOW + f"  [WP] User enum blocked (401) at {user_url}")
                findings["rest_endpoints"].append({
                    "path": user_url.replace(base, ""),
                    "status": 401,
                    "note": "authentication required"
                })
        except Exception:
            continue

    # Probe other interesting endpoints
    probe_paths = [
        ("/wp-json/wp/v2/posts?per_page=3", "Posts API"),
        ("/wp-json/wp/v2/categories", "Categories API"),
        ("/xmlrpc.php", "XML-RPC"),
        ("/wp-login.php", "Login page"),
        ("/readme.html", "WP Readme (version exposure)"),
        ("/wp-content/debug.log", "Debug log"),
        ("/wp-config.php.bak", "Config backup"),
        ("/wp-content/uploads/", "Uploads directory listing"),
    ]
    for path, label in probe_paths:
        try:
            url = base + path
            resp = request_with_retry(url, timeout=6, retries=1,
                                       base_delay=0.5, rotate_ua=True)
            if resp.status_code == 200:
                size = len(resp.text)
                findings["exposed_paths"].append({
                    "path": path, "label": label, "status": 200, "size": size
                })
                severity = Fore.RED if "debug" in path.lower() or "config" in path.lower() else Fore.GREEN
                print(severity + f"  [WP] {label} accessible: {path} ({size} bytes)")
            elif resp.status_code == 403:
                findings["exposed_paths"].append({
                    "path": path, "label": label, "status": 403, "note": "forbidden"
                })
        except Exception:
            continue

    return findings


# ---------------------------------------------------------------------------
# Laravel specific intelligence
# ---------------------------------------------------------------------------

def probe_laravel(target_url: str, html_content: str = ""):
    """
    Laravel specific recon:
    - .env exposure check
    - Ignition/Whoops debug mode detection
    - Telescope dashboard
    - Horizon dashboard
    - Storage log exposure
    - Debug mode indicators in HTML
    """
    findings = {
        "debug_mode": False,
        "exposed_paths": [],
        "env_leaked": False,
        "debug_evidence": [],
    }

    base = target_url.rstrip("/")

    # Check HTML for debug indicators
    debug_patterns = [
        (r'Whoops!.*?There was an error', "Whoops error handler active"),
        (r'Ignition\s', "Ignition error page detected"),
        (r'APP_DEBUG.*?true', "APP_DEBUG=true in HTML"),
        (r'laravel_session', "Laravel session cookie reference"),
        (r'"exception":\s*".*?\\\\.*?Exception"', "Laravel exception trace in JSON"),
        (r'vendor/laravel', "Laravel vendor path exposed"),
    ]
    for pattern, evidence in debug_patterns:
        if re.search(pattern, html_content, re.I | re.DOTALL):
            findings["debug_mode"] = True
            findings["debug_evidence"].append(evidence)
            print(Fore.RED + f"  [LARAVEL] Debug indicator: {evidence}")

    # Probe sensitive endpoints
    probe_items = [
        ("/.env", "Environment file", True),
        ("/_ignition/health-check", "Ignition health check", False),
        ("/telescope", "Telescope dashboard", False),
        ("/telescope/requests", "Telescope requests", False),
        ("/horizon", "Horizon dashboard", False),
        ("/horizon/api/stats", "Horizon API stats", False),
        ("/storage/logs/laravel.log", "Laravel log file", True),
        ("/api", "API base route", False),
        ("/.env.backup", "Env backup file", True),
        ("/.env.local", "Env local file", True),
        ("/.env.production", "Env production file", True),
    ]

    for path, label, is_critical in probe_items:
        try:
            url = base + path
            resp = request_with_retry(url, timeout=6, retries=1,
                                       base_delay=0.5, rotate_ua=True)

            if resp.status_code == 200:
                content_preview = resp.text[:200].strip()
                entry = {
                    "path": path,
                    "label": label,
                    "status": 200,
                    "size": len(resp.text),
                    "critical": is_critical,
                }

                # Check if .env actually contains env vars
                if ".env" in path and ("APP_KEY=" in resp.text or
                                        "DB_PASSWORD=" in resp.text or
                                        "APP_DEBUG=" in resp.text):
                    findings["env_leaked"] = True
                    entry["env_keys_found"] = True
                    print(Fore.RED +
                          f"  [LARAVEL] CRITICAL — .env file exposed: {path}")
                    print(Fore.RED +
                          f"    |__ Contains environment variables!")
                    # Extract key names (not values!) for reporting
                    env_keys = re.findall(r'^([A-Z][A-Z0-9_]+)=', resp.text, re.M)
                    entry["env_key_names"] = env_keys[:30]
                    if env_keys:
                        print(Fore.WHITE +
                              f"    |__ Keys found: {', '.join(env_keys[:10])}"
                              f"{'...' if len(env_keys) > 10 else ''}")

                elif "ignition" in path.lower() and resp.status_code == 200:
                    findings["debug_mode"] = True
                    findings["debug_evidence"].append(f"{label} accessible")
                    print(Fore.RED + f"  [LARAVEL] {label} accessible: {path}")

                elif "telescope" in path.lower() or "horizon" in path.lower():
                    # Check if it's a real dashboard, not a redirect
                    if "telescope" in resp.text.lower() or "horizon" in resp.text.lower():
                        print(Fore.RED + f"  [LARAVEL] {label} accessible: {path}")
                    else:
                        entry["note"] = "responded but may be redirected"
                        print(Fore.YELLOW +
                              f"  [LARAVEL] {label}: {path} -> 200 but content unclear")
                else:
                    print(Fore.GREEN + f"  [LARAVEL] {label}: {path} -> {resp.status_code}")

                findings["exposed_paths"].append(entry)

            elif resp.status_code == 500:
                # 500 on _ignition means debug mode might be on
                if "ignition" in path.lower() or "telescope" in path.lower():
                    findings["exposed_paths"].append({
                        "path": path, "label": label, "status": 500,
                        "note": "server error (debug mode might expose stack trace)"
                    })
        except Exception:
            continue

    return findings


# ---------------------------------------------------------------------------
# Main framework intelligence runner
# ---------------------------------------------------------------------------

def run_framework_intel(target_url: str, html_content: str, headers: dict,
                         results: dict = None, results_lock: threading.Lock = None,
                         output_file: str = None):
    """
    Run full framework-specific intelligence:
    1. Fingerprint frameworks from HTML + headers
    2. Run framework-specific probes based on detection
    3. Store results in global RESULTS dict

    Returns FrameworkIntelResult with all findings.
    """
    intel = FrameworkIntelResult()
    output_lines = []

    # -- Step 1: Fingerprinting -----------------------------------------------
    print(Fore.YELLOW + "\n[FRAMEWORK] Running framework fingerprinting...")
    frameworks = fingerprint_frameworks(html_content, headers)
    intel.frameworks = frameworks

    if not frameworks:
        print(Fore.YELLOW + "[FRAMEWORK] No specific framework detected.")
        output_lines.append("\n[FRAMEWORK] No specific framework detected.")
    else:
        for fw in frameworks:
            ver_str = f" v{fw.version}" if fw.version else ""
            print(Fore.GREEN +
                  f"[FRAMEWORK] Detected: {fw.name}{ver_str} "
                  f"[{fw.confidence}] — {', '.join(fw.evidence)}")
            output_lines.append(
                f"[FRAMEWORK] {fw.name}{ver_str} [{fw.confidence}] "
                f"evidence: {', '.join(fw.evidence)}"
            )

    framework_names = {fw.name for fw in frameworks}

    # -- Step 2: Framework-specific probes ------------------------------------
    # Next.js intelligence
    if "Next.js" in framework_names:
        print(Fore.YELLOW + "\n[FRAMEWORK] Running Next.js specific recon...")
        output_lines.append("\n[FRAMEWORK] Next.js Recon:")
        nextjs_fw = next(f for f in frameworks if f.name == "Next.js")
        nextjs_result = probe_nextjs(target_url, html_content,
                                      build_id=nextjs_fw.version)
        intel.nextjs_data_routes = nextjs_result.get("data_routes", [])
        if nextjs_result.get("api_routes"):
            for route in nextjs_result["api_routes"]:
                output_lines.append(f"  [NEXT.JS] API: {route}")
        if nextjs_result.get("build_id"):
            output_lines.append(f"  [NEXT.JS] buildId: {nextjs_result['build_id']}")

    # WordPress intelligence
    if "WordPress" in framework_names:
        print(Fore.YELLOW + "\n[FRAMEWORK] Running WordPress specific recon...")
        output_lines.append("\n[FRAMEWORK] WordPress Recon:")
        wp_result = probe_wordpress(target_url)
        intel.wp_users = wp_result.get("users", [])
        intel.wp_endpoints = wp_result.get("rest_endpoints", [])
        if wp_result.get("users"):
            output_lines.append(
                f"  [WP] {len(wp_result['users'])} users enumerated!"
            )
        for ep in wp_result.get("exposed_paths", []):
            output_lines.append(
                f"  [WP] {ep['label']}: {ep['path']} -> {ep['status']}"
            )

    # Laravel intelligence
    if "Laravel" in framework_names or "Laravel Mix" in framework_names:
        print(Fore.YELLOW + "\n[FRAMEWORK] Running Laravel specific recon...")
        output_lines.append("\n[FRAMEWORK] Laravel Recon:")
        laravel_result = probe_laravel(target_url, html_content)
        intel.laravel_findings = [laravel_result]
        if laravel_result.get("debug_mode"):
            output_lines.append(
                "  [LARAVEL] DEBUG MODE DETECTED — "
                f"evidence: {', '.join(laravel_result.get('debug_evidence', []))}"
            )
        if laravel_result.get("env_leaked"):
            output_lines.append("  [LARAVEL] CRITICAL — .env file exposed!")
        for ep in laravel_result.get("exposed_paths", []):
            output_lines.append(
                f"  [LARAVEL] {ep['label']}: {ep['path']} -> {ep['status']}"
            )

    # -- Step 3: Store results -------------------------------------------------
    if results is not None and results_lock is not None:
        with results_lock:
            results["framework_intel"] = intel.to_dict()

    if output_file and output_lines:
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write('\n'.join(output_lines) + '\n')

    return intel
