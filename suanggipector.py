#!/usr/bin/env python3
# suanggipector v2.2
# A JavaScript Inspector for Reconnaissance
# Deep JS chunk discovery, 40+ secret patterns, entropy analysis,
# source map discovery, WAF detection, and false-positive filtering.
#
# https://github.com/suanggiLaut/suanggipector

import requests
import argparse
import re
import os
import json
import math
import time
import random
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import init, Fore, Style

init(autoreset=True)

# ---------------------------------------------------------------------------
# REGEX PATTERNS — provider-specific first, generic last
# ---------------------------------------------------------------------------
REGEX_PATTERNS = {
    # ── URL / Endpoint extraction ──────────────────────────────────────────
    'URL Paths': (
        r'''(?:["'`])'''
        r'''('''
            r'''/(?:[a-zA-Z0-9]'''
            r'''[a-zA-Z0-9_./@:~-]*'''
            r'''(?:\?[a-zA-Z0-9_.&=%+-]*)?)'''
        r''')'''
        r'''(?:["'`])'''
    ),

    # ── Cloud provider keys ────────────────────────────────────────────────
    'Google API Key':              r'AIza[0-9A-Za-z\-_]{35}',
    'Google OAuth Client ID':      r'[0-9]{5,30}-[a-z0-9_]{28,64}\.apps\.googleusercontent\.com',
    'GCP Service Account':         r'[a-z0-9_-]{6,30}@[a-z0-9_-]{6,30}\.iam\.gserviceaccount\.com',
    'Amazon AWS Access Key ID':    r'(?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}',
    'Amazon AWS Secret Key':       r'''(?i)(?:aws|amazon).{0,40}?["\']([0-9a-zA-Z/+]{40})["\']''',
    'Azure Storage Key':           r'(?i)(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*[A-Za-z0-9+/=]{44,}',
    'Azure Client Secret':         r'(?i)(?:client.?secret|azure.?secret)\s*[:=]\s*["\']?([a-zA-Z0-9~_.]{34,})["\']?',

    # ── Firebase / GCP realtime DB ─────────────────────────────────────────
    'Firebase URL':                r'https://[a-zA-Z0-9_-]+\.firebaseio\.com',
    'Firebase Cloud Messaging':    r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}',

    # ── Code hosting / CI ──────────────────────────────────────────────────
    'GitHub Token (classic)':      r'ghp_[A-Za-z0-9]{36,255}',
    'GitHub Token (fine-grained)': r'github_pat_[A-Za-z0-9_]{22,255}',
    'GitHub Token (other)':        r'gh[ousr]_[A-Za-z0-9]{36,255}',
    'GitHub App Token':            r'(?:ghu|ghs)_[A-Za-z0-9]{36,255}',
    'GitLab Token':                r'glpat-[A-Za-z0-9\-_]{20,}',
    'Bitbucket App Password':      r'(?i)bitbucket.{0,40}?["\']([A-Za-z0-9]{20,})["\']',

    # ── Communication / chat ───────────────────────────────────────────────
    'Slack Token':                 r'xox[baprs]-[0-9A-Za-z\-]{10,72}',
    'Slack Webhook':               r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}',
    'Discord Bot Token':           r'(?:N|M|O)[A-Za-z0-9]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}',
    'Discord Webhook':             r'https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,70}',
    'Telegram Bot Token':          r'[0-9]{5,10}:AA[A-Za-z0-9_-]{33}',
    'Microsoft Teams Webhook':     r'https://[a-z0-9-]+\.webhook\.office\.com/webhookb2/[a-f0-9-]+',

    # ── Payment / fintech ──────────────────────────────────────────────────
    'Stripe Key':                  r'(?:sk|rk|pk)_(?:live|test)_[0-9a-zA-Z]{16,247}',
    'Square Access Token':         r'sq0atp-[0-9A-Za-z\-_]{22,}',
    'Square OAuth Secret':         r'sq0csp-[0-9A-Za-z\-_]{43,}',
    'PayPal Braintree Token':      r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'Shopify Token':               r'shpat_[a-fA-F0-9]{32}',
    'Shopify Shared Secret':       r'shpss_[a-fA-F0-9]{32}',

    # ── Email / messaging SaaS ─────────────────────────────────────────────
    'Twilio API Key':              r'SK[0-9a-fA-F]{32}',
    'Twilio Account SID':          r'AC[0-9a-fA-F]{32}',
    'SendGrid API Key':            r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
    'Mailgun API Key':             r'key-[0-9a-zA-Z]{32}',
    'Mailchimp API Key':           r'[0-9a-f]{32}-us[0-9]{1,2}',
    'Postmark Token':              r'(?i)(?:postmark|pmak).{0,20}?["\']([a-f0-9-]{36})["\']',

    # ── Monitoring / observability ─────────────────────────────────────────
    'Datadog API Key':             r'(?i)(?:datadog|dd).{0,30}?["\']([a-f0-9]{32})["\']',
    'New Relic Key':               r'NRAK-[A-Z0-9]{27}',
    'New Relic Insights Key':      r'NRI(?:I|Q)-[A-Za-z0-9-_]{32}',
    'Sentry DSN':                  r'https://[a-f0-9]{32}@(?:o[0-9]+\.)?(?:sentry\.io|[a-z0-9.-]+)/[0-9]+',
    'PagerDuty Key':               r'(?i)(?:pagerduty|pd).{0,20}?["\']([a-zA-Z0-9+/]{20})["\']',

    # ── CDN / DNS / hosting ────────────────────────────────────────────────
    'Cloudflare API Key':          r'(?i)(?:cloudflare|cf).{0,30}?["\']([a-f0-9]{37})["\']',
    'Cloudflare API Token':        r'(?i)(?:cloudflare|cf).{0,30}?["\']([A-Za-z0-9_-]{40})["\']',
    'DigitalOcean Token':          r'dop_v1_[a-f0-9]{64}',
    'Heroku API Key':              r'(?i)heroku.{0,30}?["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']',
    'Vercel Token':                r'(?i)(?:vercel|zeit).{0,20}?["\']([A-Za-z0-9]{24})["\']',
    'Netlify Token':               r'(?i)netlify.{0,20}?["\']([a-zA-Z0-9_-]{40,})["\']',

    # ── Search / maps / analytics ──────────────────────────────────────────
    'Algolia API Key':             r'(?i)(?:algolia|alg).{0,30}?["\']([a-f0-9]{32})["\']',
    'Mapbox Token':                r'(?:pk|sk)\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}',

    # ── Package registry tokens ────────────────────────────────────────────
    'npm Token':                   r'npm_[A-Za-z0-9]{36}',
    'PyPI Token':                  r'pypi-[A-Za-z0-9_-]{50,}',
    'NuGet API Key':               r'oy2[a-z0-9]{43}',
    'RubyGems Token':              r'rubygems_[a-f0-9]{48}',

    # ── Auth tokens / general ──────────────────────────────────────────────
    'JWT':                         r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_.+/=-]{10,}',
    'Bearer Token (header)':       r'''(?i)["']?(?:authorization|bearer)["']?\s*[:=]\s*["']?Bearer\s+([A-Za-z0-9_.~+/=-]{20,})["']?''',
    'Private Key Header':          r'-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE\s+KEY-----',
    'OAuth Client Secret':         r'''(?i)(?:client.?secret|consumer.?secret)\s*[:=]\s*["']([a-zA-Z0-9_-]{16,})["\']''',
    'Basic Auth Embedded':         r'https?://[^"\'\s]+:[^"\'\s]+@[^"\'\s]+',

    # ── Catch-all generic pattern (MEDIUM confidence) ──────────────────────
    'Generic API Key/Secret': (
        r'''(?i)'''
        r'''["']'''
        r'''(api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?key'''
        r'''|auth[_-]?token|private[_-]?key|client[_-]?id|app[_-]?secret'''
        r'''|encryption[_-]?key|signing[_-]?key|service[_-]?key'''
        r'''|database[_-]?password|db[_-]?password|admin[_-]?password'''
        r'''|master[_-]?key|root[_-]?password)'''
        r'''["']'''
        r'''\s*[:=]\s*'''
        r'''["']([a-zA-Z0-9_.+/=-]{8,})["\']'''
    ),
}

# ---------------------------------------------------------------------------
# Suspicious-string patterns (base64, high-entropy)
# ---------------------------------------------------------------------------
SUSPICIOUS_STRING_PATTERN = r'["\']([A-Za-z0-9+/=]{20,})["\']'
HIGH_ENTROPY_PATTERN      = r'["\']([a-zA-Z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]{16,})["\']'

# ---------------------------------------------------------------------------
# False-positive allow/deny list — expanded to cover common JS build noise
# ---------------------------------------------------------------------------
FALSE_POSITIVE_HINTS = (
    'function', 'webpack', 'chunk', 'react', 'vendor', 'polyfill',
    'undefined', 'prototype', 'node_modules', '.css', '.woff', '.svg',
    'lorem', 'xxxxxxxx', 'placeholder', 'example.com', 'test123',
    # -- v2.1 additions --
    'sourcemappingurl', 'use strict', 'object.defineproperty',
    'object.create', 'module.exports', 'exports.default',
    'createelement', 'classname', 'stylesheet', '__webpack',
    'webpackchunk', 'regeneratorruntime', 'asyncgenerator',
    'abcdefghijklmnop', 'qrstuvwxyz', '0123456789',
    'data:image', 'data:font', 'data:application',
    '.png', '.jpg', '.gif', '.woff2', '.ttf', '.eot',
    'getprototypeof', 'hasownproperty', 'isprototypeof',
    'tostring', 'constructor', 'configurable',
)

_FP_HINT_SET = tuple(h.lower() for h in FALSE_POSITIVE_HINTS)

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1',
]

# ---------------------------------------------------------------------------
# Confidence classification
# ---------------------------------------------------------------------------
HIGH_CONFIDENCE_TYPES = {
    'Google API Key', 'Google OAuth Client ID', 'GCP Service Account',
    'Amazon AWS Access Key ID', 'Amazon AWS Secret Key',
    'Azure Storage Key',
    'Firebase URL', 'Firebase Cloud Messaging',
    'GitHub Token (classic)', 'GitHub Token (fine-grained)',
    'GitHub Token (other)', 'GitHub App Token', 'GitLab Token',
    'Slack Token', 'Slack Webhook',
    'Discord Bot Token', 'Discord Webhook',
    'Telegram Bot Token', 'Microsoft Teams Webhook',
    'Stripe Key', 'Square Access Token', 'Square OAuth Secret',
    'PayPal Braintree Token', 'Shopify Token', 'Shopify Shared Secret',
    'Twilio API Key', 'Twilio Account SID',
    'SendGrid API Key', 'Mailgun API Key', 'Mailchimp API Key',
    'New Relic Key', 'New Relic Insights Key', 'Sentry DSN',
    'DigitalOcean Token',
    'npm Token', 'PyPI Token', 'NuGet API Key', 'RubyGems Token',
    'JWT', 'Private Key Header', 'Mapbox Token',
    'Basic Auth Embedded',
}

_STATIC_ASSET_RE = re.compile(
    r'\.(?:css|js|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|mp[34]|webp|webm|avif|pdf)$',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Deep JS chunk discovery — regex patterns to find referenced JS files
# inside other JS files (webpack chunks, Nuxt/Vite lazy imports, etc.)
# ---------------------------------------------------------------------------
_JS_CHUNK_PATTERNS = [
    # Direct path references: "/_nuxt/BxAbCd.js", '/_nuxt/chunk-abc.mjs'
    re.compile(
        r'''["'`](/_nuxt/[A-Za-z0-9_.$-]+\.(?:js|mjs))["'`]'''
    ),
    # Webpack/Vite chunk loading: e.p + "chunk-name" + ".hash.js"
    # Captures the filename part like "CxAbCdEf.js" near _nuxt references
    re.compile(
        r'''["'`]([A-Za-z0-9_$-]{4,}\.(?:js|mjs))["'`]'''
    ),
    # Dynamic import() with string literal path
    re.compile(
        r'''import\s*\(\s*["'`](\.?/[^"'`]+\.(?:js|mjs))["'`]\s*\)'''
    ),
    # Relative JS references in any framework: "./path/file.js"
    re.compile(
        r'''["'`](\./[A-Za-z0-9_./-]+\.(?:js|mjs))["'`]'''
    ),
    # Full URL references to same-origin JS
    re.compile(
        r'''["'`](https?://[^"'`\s]+\.(?:js|mjs))["'`]'''
    ),
]

# Patterns to SKIP when discovering chunks (common false positives)
_CHUNK_SKIP_PATTERNS = re.compile(
    r'(?:'
    r'node_modules|\.min\.js$|sourceMappingURL|'
    r'webpack\.runtime|hot-update|\.map$|'
    r'example\.(?:com|org|net)|localhost'
    r')',
    re.IGNORECASE,
)


def extract_js_refs_from_content(js_content, base_url):
    """
    Extract references to other JS files from within a JS file's content.
    Covers: _nuxt chunks, webpack dynamic imports, Vite lazy chunks, etc.
    Returns a set of absolute URLs.
    """
    found = set()
    parsed_base = urlparse(base_url)
    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    for pattern in _JS_CHUNK_PATTERNS:
        for match in pattern.finditer(js_content):
            ref = match.group(1)

            # Skip obvious non-chunk references
            if _CHUNK_SKIP_PATTERNS.search(ref):
                continue

            # Skip very short filenames (likely variable names, not real files)
            basename = ref.rsplit('/', 1)[-1] if '/' in ref else ref
            if len(basename) < 4:
                continue

            # Build absolute URL
            if ref.startswith('http://') or ref.startswith('https://'):
                # Full URL — only keep if same origin
                ref_parsed = urlparse(ref)
                if ref_parsed.netloc == parsed_base.netloc:
                    found.add(ref)
            elif ref.startswith('/'):
                # Absolute path
                found.add(base_origin + ref)
            elif ref.startswith('./') or ref.startswith('../'):
                # Relative path
                found.add(urljoin(base_url, ref))
            else:
                # Bare filename like "CxAbCdEf.js" — resolve relative to
                # the directory of the current JS file (e.g. /_nuxt/)
                js_dir = base_url.rsplit('/', 1)[0] + '/'
                found.add(js_dir + ref)

    return found


def deep_discover_js_chunks(initial_js_urls, base_target_url, concurrency=8,
                             delay_min=0.0, delay_max=0.0, retries=3,
                             max_depth=3, max_files=200):
    """
    BFS crawl: starting from initial JS URLs, fetch each file, extract
    references to other JS files, and repeat until no new files are found
    or limits are reached.

    Returns:
        dict mapping JS URL -> response text (content) for all discovered files
    """
    parsed_target = urlparse(base_target_url)
    target_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"

    # Track all known URLs and their content
    fetched = {}       # url -> content
    failed = set()     # urls that failed to fetch
    queue = set(initial_js_urls)  # urls to fetch next
    all_known = set(initial_js_urls)

    depth = 0
    while queue and depth < max_depth and len(fetched) < max_files:
        depth += 1
        batch = list(queue)
        queue = set()

        print(Fore.YELLOW + f"\n[DEEP CRAWL] Depth {depth}: fetching {len(batch)} JS files...")

        def _fetch_one(url):
            if delay_max > 0:
                time.sleep(random.uniform(delay_min, delay_max))
            try:
                resp = request_with_retry(url, timeout=10, retries=retries,
                                           base_delay=1.0, rotate_ua=True)
                resp.raise_for_status()
                return url, resp.text, None
            except requests.exceptions.RequestException as e:
                return url, None, str(e)

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {executor.submit(_fetch_one, u): u for u in batch}
            done_count = 0
            for future in as_completed(futures):
                done_count += 1
                url, content, error = future.result()
                if content is not None:
                    fetched[url] = content
                    status = Fore.GREEN + "OK"
                    print(Fore.CYAN + f"  [{done_count}/{len(batch)}] {url} -> {status}")

                    # Extract new JS references from this file
                    new_refs = extract_js_refs_from_content(content, url)
                    for ref_url in new_refs:
                        # Only follow same-origin references
                        if not ref_url.startswith(target_origin):
                            continue
                        if ref_url not in all_known:
                            all_known.add(ref_url)
                            queue.add(ref_url)
                else:
                    failed.add(url)
                    status = Fore.RED + f"FAILED ({error})"
                    print(Fore.CYAN + f"  [{done_count}/{len(batch)}] {url} -> {status}")

        if queue:
            print(Fore.YELLOW + f"[DEEP CRAWL] Discovered {len(queue)} new JS chunks to scan...")

    total = len(fetched)
    discovered = total - len(initial_js_urls & set(fetched.keys()))
    if discovered > 0:
        print(Fore.GREEN + f"[DEEP CRAWL] Total: {total} JS files "
                            f"({discovered} extra chunks discovered via deep crawl)")
    else:
        print(Fore.YELLOW + f"[DEEP CRAWL] No additional chunks discovered beyond initial {len(initial_js_urls)} files.")

    return fetched, failed


def is_probably_noise(value):
    """Quick filter to discard strings that are clearly not secrets."""
    low = value.lower()
    if any(hint in low for hint in _FP_HINT_SET):
        return True
    if len(set(value)) <= 3:
        return True
    if re.fullmatch(r'[0-9a-fA-F]+', value) and len(value) < 32:
        return True
    return False


def is_noise_endpoint(path):
    """Return True if the URL path is almost certainly a static asset, not an API."""
    if _STATIC_ASSET_RE.search(path):
        return True
    if '/' not in path.lstrip('/') and '.' in path:
        return True
    return False


def request_with_retry(url, headers=None, timeout=15, retries=3, base_delay=1.0, rotate_ua=True):
    """GET with retry + exponential backoff and (optional) UA rotation + jitter delay."""
    last_exc = None
    for attempt in range(1, retries + 1):
        req_headers = dict(headers or {})
        if rotate_ua:
            req_headers['User-Agent'] = random.choice(USER_AGENTS)
        try:
            resp = requests.get(url, headers=req_headers, timeout=timeout, verify=False)
            if resp.status_code in (429, 503):
                wait = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 0.5)
                print(Fore.YELLOW + f"[RATE LIMIT] {url} -> HTTP {resp.status_code}, "
                                     f"waiting {wait:.1f}s (attempt {attempt}/{retries})")
                time.sleep(wait)
                continue
            return resp
        except requests.exceptions.RequestException as e:
            last_exc = e
            wait = base_delay * (2 ** (attempt - 1))
            time.sleep(wait)
    if last_exc:
        raise last_exc
    return None


# Global, thread-safe result store
RESULTS_LOCK = threading.Lock()
RESULTS = {
    "target": None,
    "waf_detected": [],
    "js_files": [],
    "js_files_discovered": [],
    "js_files_failed": [],
    "source_maps": [],
    "endpoints": set(),
    "findings": [],
    "high_entropy": [],
    "suspicious_b64": [],
}


def calculate_shannon_entropy(data):
    if not data:
        return 0
    counter = Counter(data)
    length = len(data)
    entropy = 0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def mask(value):
    return value[:4] + "***" + value[-4:] if len(value) > 10 else value


def print_banner():
    banner = r"""
███████╗██╗   ██╗ █████╗ ███╗   ██╗ ██████╗  ██████╗ ██╗██████╗ ███████╗ ██████╗████████╗ ██████╗ ██████╗
██╔════╝██║   ██║██╔══██╗████╗  ██║██╔════╝ ██╔════╝ ██║██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
███████╗██║   ██║███████║██╔██╗ ██║██║  ███╗██║  ███╗██║██████╔╝█████╗  ██║        ██║   ██║   ██║██████╔╝
╚════██║██║   ██║██╔══██║██║╚██╗██║██║   ██║██║   ██║╚═╝██╔═══╝ ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
███████║╚██████╔╝██║  ██║██║ ╚████║╚██████╔╝╚██████╔╝██╗██║     ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝

    suanggipector v2.2 — JavaScript Reconnaissance Scanner
    Deep Chunk Discovery | 40+ Secret Patterns | Entropy Analysis
"""
    print(Fore.CYAN + banner)


def detect_waf(response):
    waf_signatures = {
        'Cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid'],
        'AWS WAF': ['x-amzn-requestid', 'x-amz-cf-id', 'x-amz-cf-pop'],
        'Akamai': ['x-akamai-transformed', 'x-akamai-request-id'],
        'Imperva': ['x-iinfo', 'x-cdn', 'incap-ses'],
        'Sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
        'F5 BIG-IP': ['x-wa-info', 'x-cnection'],
        'Fortinet': ['x-fortigate', 'fortigate'],
        'Barracuda': ['x-barracuda'],
        'ModSecurity': ['x-mod-security'],
        'Wordfence': ['x-wordfence'],
    }
    detected_wafs = []
    headers = response.headers
    header_keys_lower = [k.lower() for k in headers.keys()]

    for waf_name, signatures in waf_signatures.items():
        for sig in signatures:
            if sig.lower() in header_keys_lower:
                detected_wafs.append(waf_name)
                break

    if response.status_code == 403:
        if 'request blocked' in response.text.lower() or 'access denied' in response.text.lower():
            if 'Cloudflare' not in detected_wafs:
                detected_wafs.append('Generic WAF (403 Block)')

    if response.status_code == 406:
        detected_wafs.append('Possible WAF (406 Not Acceptable)')

    return list(set(detected_wafs))


def get_scripts(url, output_file=None):
    """Extract external JS file URLs and inline script content from target."""
    print(Fore.YELLOW + f"[INFO] Crawling target: {url}")
    print(Fore.RED + "[WARNING] verify=False — SSL certificate not validated. Use for testing only!")

    js_files = set()
    inline_scripts = []
    detected_waf = None

    try:
        response = request_with_retry(url, timeout=15, retries=3, base_delay=1.0, rotate_ua=True)

        detected_waf = detect_waf(response)
        if detected_waf:
            print(Fore.RED + f"[WAF DETECTED] Detected: {', '.join(detected_waf)}")
            RESULTS["waf_detected"] = detected_waf
            if output_file:
                with open(output_file, 'a', encoding='utf-8') as f:
                    f.write(f"\n[WAF DETECTED] {', '.join(detected_waf)} at {url}\n")
        else:
            print(Fore.GREEN + "[OK] No WAF detected from response headers.")

        response.raise_for_status()

        # Also extract JS refs from the HTML page source itself (inline loaders)
        html_text = response.text
        soup = BeautifulSoup(html_text, 'html.parser')

        for script_tag in soup.find_all('script', src=True):
            full_url = urljoin(url, script_tag.get('src'))
            js_files.add(full_url)

        # Extract JS refs from inline <script> blocks and raw HTML
        # (catches preload/prefetch links and inline webpack manifests)
        for link_tag in soup.find_all('link', rel=True):
            rel = ' '.join(link_tag.get('rel', []))
            href = link_tag.get('href', '')
            if ('preload' in rel or 'prefetch' in rel or 'modulepreload' in rel):
                if href.endswith('.js') or href.endswith('.mjs'):
                    js_files.add(urljoin(url, href))

        for script_tag in soup.find_all('script', src=False):
            if script_tag.string:
                inline_scripts.append(script_tag.string)
                # Also look for JS refs in inline scripts (webpack manifest, etc.)
                inline_refs = extract_js_refs_from_content(script_tag.string, url)
                js_files.update(inline_refs)

    except requests.exceptions.SSLError as e:
        print(Fore.RED + f"[SSL ERROR] {e}")
    except requests.exceptions.ConnectionError as e:
        print(Fore.RED + f"[CONNECTION ERROR] Failed to connect to {url}: {e}")
    except requests.exceptions.Timeout as e:
        print(Fore.RED + f"[TIMEOUT] Connection timeout for {url}: {e}")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[ERROR] Failed to access {url}: {e}")

    return list(js_files), inline_scripts, detected_waf


def discover_source_map(js_url, js_content, output_file=None):
    match = re.search(r'//[#@]\s*sourceMappingURL=(\S+)', js_content)
    if not match:
        return None

    map_url = urljoin(js_url, match.group(1))
    try:
        resp = request_with_retry(map_url, timeout=10, retries=2, base_delay=0.5, rotate_ua=True)
        resp.raise_for_status()
        map_data = resp.json()
    except (requests.exceptions.RequestException, ValueError):
        return None

    sources = map_data.get('sources', [])
    if not sources:
        return None

    header = Fore.MAGENTA + f"\n[SOURCE MAP] Source map found: {map_url}"
    print(header)
    lines = [f"\n[SOURCE MAP] Source map found: {map_url}"]
    for src in sources[:50]:
        line = f"  |__ {src}"
        print(Fore.WHITE + line)
        lines.append(line)
    if len(sources) > 50:
        note = f"  |__ ... and {len(sources) - 50} more files (truncated)"
        print(Fore.WHITE + note)
        lines.append(note)

    with RESULTS_LOCK:
        RESULTS["source_maps"].append({
            "js_file": js_url,
            "map_url": map_url,
            "sources": sources
        })

    if output_file:
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')

    return map_url


def scan_high_entropy_strings(content, source, entropy_threshold, output_file=None):
    output_lines = []
    found_something = False

    matches = re.findall(HIGH_ENTROPY_PATTERN, content)
    high_entropy_matches = []
    for match in matches:
        if is_probably_noise(match):
            continue
        entropy = calculate_shannon_entropy(match)
        if entropy > entropy_threshold:
            high_entropy_matches.append((match, entropy))

    if high_entropy_matches:
        seen = set()
        unique_matches = []
        for match, entropy in high_entropy_matches:
            if match not in seen:
                seen.add(match)
                unique_matches.append((match, entropy))

        if unique_matches:
            header = Fore.MAGENTA + f"\n[HIGH ENTROPY] High Entropy Strings in: {source} (Threshold: {entropy_threshold})"
            print(header)
            if output_file:
                output_lines.append(f"\n[HIGH ENTROPY] Strings in: {source} (Threshold: {entropy_threshold})")

            for match_str, entropy_val in sorted(unique_matches, key=lambda x: x[1], reverse=True):
                masked = mask(match_str)
                result = Fore.WHITE + f"  |__ Entropy: {entropy_val:.2f} | String: {masked}"
                print(result)
                if output_file:
                    output_lines.append(f"  |__ Entropy: {entropy_val:.2f} | String: {masked}")
                with RESULTS_LOCK:
                    RESULTS["high_entropy"].append({
                        "source": source, "entropy": round(entropy_val, 2), "value_masked": masked
                    })

            found_something = True

    if output_file and output_lines:
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write('\n'.join(output_lines) + '\n')

    return found_something


def scan_suspicious_b64(content, source, output_file=None):
    output_lines = []
    found_something = False

    matches = re.findall(SUSPICIOUS_STRING_PATTERN, content)
    seen = set()
    unique_matches = [m for m in matches if not (m in seen or seen.add(m))]

    candidates = [m for m in unique_matches if len(set(m)) > 4 and not is_probably_noise(m)]

    if candidates:
        header = Fore.BLUE + f"\n[BASE64] Suspicious Base64-like Strings in: {source}"
        print(header)
        if output_file:
            output_lines.append(f"\n[BASE64] Suspicious Base64-like Strings in: {source}")

        for match_str in candidates:
            masked = mask(match_str)
            result = Fore.WHITE + f"  |__ {masked}"
            print(result)
            if output_file:
                output_lines.append(f"  |__ {masked}")
            with RESULTS_LOCK:
                RESULTS["suspicious_b64"].append({"source": source, "value_masked": masked})

        found_something = True

    if output_file and output_lines:
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write('\n'.join(output_lines) + '\n')

    return found_something


def scan_content(source, content, entropy_threshold, output_file=None, do_sourcemap=False, js_url=None):
    found_something = False
    output_lines = []

    for key, pattern in REGEX_PATTERNS.items():
        matches = re.findall(pattern, content)
        if matches:
            clean = []
            seen = set()
            for m in matches:
                match_str = m if isinstance(m, str) else m[1] if len(m) > 1 else m[0]
                match_str = match_str.strip()
                if match_str in seen:
                    continue
                seen.add(match_str)

                if key == 'URL Paths':
                    if is_noise_endpoint(match_str):
                        continue
                elif is_probably_noise(match_str):
                    continue

                clean.append(match_str)

            if not clean:
                continue

            if not found_something:
                header = Fore.GREEN + f"\n[+] Findings in: {source}"
                print(header)
                if output_file:
                    output_lines.append(f"\n[+] Findings in: {source}")
                found_something = True

            result_header = Fore.CYAN + f"  |__ Potential '{key}':"
            print(result_header)
            if output_file:
                output_lines.append(f"  |__ Potential '{key}':")

            for match_str in clean:
                confidence = "HIGH" if key in HIGH_CONFIDENCE_TYPES else "MEDIUM"
                display_val = match_str if key == 'URL Paths' else f"{mask(match_str)} [{confidence}]"
                result = Fore.WHITE + f"    - {display_val}"
                print(result)
                if output_file:
                    output_lines.append(f"    - {display_val}")

                with RESULTS_LOCK:
                    RESULTS["findings"].append({
                        "source": source, "type": key,
                        "value": match_str if key == 'URL Paths' else mask(match_str),
                        "confidence": "N/A" if key == 'URL Paths' else confidence,
                    })
                    if key == 'URL Paths':
                        RESULTS["endpoints"].add(match_str)

    if output_file and output_lines:
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write('\n'.join(output_lines) + '\n')

    entropy_found = scan_high_entropy_strings(content, source, entropy_threshold, output_file)
    b64_found = scan_suspicious_b64(content, source, output_file)

    if do_sourcemap and js_url:
        discover_source_map(js_url, content, output_file)

    return found_something or entropy_found or b64_found


def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="suanggipector v2.2 — JS Reconnaissance Scanner with Deep Chunk Discovery, "
                     "Entropy Analysis, Source Map Discovery & WAF Detection",
        epilog="Example: python suanggipector.py -u https://target.com -o results.txt --json results.json"
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan.")
    parser.add_argument("-o", "--output", help="Save output to .txt file.")
    parser.add_argument("--json", help="Save structured results to JSON file.")
    parser.add_argument("-e", "--entropy", type=float, default=5.0,
                         help="Shannon Entropy threshold (default: 5.0).")
    parser.add_argument("--no-entropy", action="store_true",
                         help="Disable entropy scanning.")
    parser.add_argument("--no-sourcemap", action="store_true",
                         help="Disable source map (.js.map) discovery.")
    parser.add_argument("--no-deep-crawl", action="store_true",
                         help="Disable deep chunk discovery (only scan JS from <script> tags).")
    parser.add_argument("--crawl-depth", type=int, default=3,
                         help="Maximum deep crawl depth (default: 3).")
    parser.add_argument("--max-js-files", type=int, default=200,
                         help="Maximum number of JS files to scan (default: 200).")
    parser.add_argument("-c", "--concurrency", type=int, default=8,
                         help="Number of parallel worker threads (default: 8).")
    parser.add_argument("--delay-min", type=float, default=0.0,
                         help="Minimum delay (seconds) before each JS request (default: 0).")
    parser.add_argument("--delay-max", type=float, default=0.0,
                         help="Maximum delay (seconds) before each JS request (default: 0).")
    parser.add_argument("--retries", type=int, default=3,
                         help="Number of retries with exponential backoff (default: 3).")
    args = parser.parse_args()

    entropy_threshold = args.entropy
    do_sourcemap = not args.no_sourcemap

    requests.packages.urllib3.disable_warnings()
    print(Fore.YELLOW + "[WARNING] SSL verification disabled (verify=False). InsecureRequestWarning suppressed.")

    target_url = args.url
    output_file = args.output
    RESULTS["target"] = target_url

    if output_file:
        print(Fore.YELLOW + f"[INFO] Results will be saved to: {output_file}")
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=== suanggipector Recon Results (v2.2) ===\n")
            f.write(f"Target: {target_url}\n")
            f.write(f"Entropy Threshold: {entropy_threshold}\n")
            f.write(f"Deep Crawl: {'OFF' if args.no_deep_crawl else f'ON (depth={args.crawl_depth}, max={args.max_js_files})'}\n")
            f.write(f"Scan Time: {__import__('datetime').datetime.now()}\n")
            f.write("=" * 50 + "\n")

    js_links, inline_scripts, waf_info = get_scripts(target_url, output_file)

    if not js_links and not inline_scripts:
        print(Fore.YELLOW + "[INFO] No JavaScript files or inline scripts found.")
        if waf_info:
            print(Fore.RED + f"[INFO] WAF {', '.join(waf_info)} may be blocking content extraction.")
        _finalize_json(args.json)
        return

    if js_links:
        initial_count = len(js_links)
        print(Fore.YELLOW + f"\n[INFO] Found {initial_count} JS files from main page.")

        if not args.no_entropy:
            print(Fore.MAGENTA + f"[ENTROPY] Shannon Entropy threshold: {entropy_threshold}")
        if do_sourcemap:
            print(Fore.MAGENTA + "[SOURCEMAP] Auto-discovery active.")

        # ── Deep chunk discovery ──────────────────────────────────────────
        if not args.no_deep_crawl:
            print(Fore.YELLOW + f"[DEEP CRAWL] Mode active — depth={args.crawl_depth}, "
                                 f"max_files={args.max_js_files}")
            fetched_map, failed_urls = deep_discover_js_chunks(
                initial_js_urls=set(js_links),
                base_target_url=target_url,
                concurrency=args.concurrency,
                delay_min=args.delay_min,
                delay_max=args.delay_max,
                retries=args.retries,
                max_depth=args.crawl_depth,
                max_files=args.max_js_files,
            )

            all_js_urls = list(fetched_map.keys())
            discovered_extra = [u for u in all_js_urls if u not in js_links]

            RESULTS["js_files"] = list(js_links)
            RESULTS["js_files_discovered"] = discovered_extra
            for fu in failed_urls:
                RESULTS["js_files_failed"].append({"url": fu, "error": "fetch failed"})

            if discovered_extra:
                print(Fore.GREEN + f"\n[DEEP CRAWL] +{len(discovered_extra)} extra chunks discovered!")
                if output_file:
                    with open(output_file, 'a', encoding='utf-8') as f:
                        f.write(f"\n[DEEP CRAWL] {len(discovered_extra)} extra JS chunks discovered:\n")
                        for u in discovered_extra[:50]:
                            f.write(f"  - {u}\n")
                        if len(discovered_extra) > 50:
                            f.write(f"  ... and {len(discovered_extra) - 50} more\n")

            # Now scan all fetched content
            print(Fore.YELLOW + f"\n[INFO] Scanning {len(fetched_map)} JS files total...")
            scan_count = 0
            for js_url, js_content in fetched_map.items():
                scan_count += 1
                print(Fore.CYAN + f"[{scan_count}/{len(fetched_map)}] Scanning: {js_url}")
                scan_content(js_url, js_content, entropy_threshold, output_file,
                             do_sourcemap=do_sourcemap, js_url=js_url)

        else:
            # ── Original mode: no deep crawl ──────────────────────────────
            print(Fore.YELLOW + f"[INFO] Deep crawl disabled. Scanning {initial_count} JS files...")
            RESULTS["js_files"] = js_links

            with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
                futures = {
                    executor.submit(_fetch_and_scan_simple, link, entropy_threshold,
                                     output_file, do_sourcemap,
                                     args.delay_min, args.delay_max, args.retries): link
                    for link in js_links
                }
                done_count = 0
                for future in as_completed(futures):
                    link = futures[future]
                    done_count += 1
                    try:
                        _, success, error = future.result()
                        status = Fore.GREEN + "OK" if success else Fore.RED + f"FAILED ({error})"
                        print(Fore.CYAN + f"[{done_count}/{len(js_links)}] {link} -> {status}")
                    except Exception as e:
                        print(Fore.RED + f"[{done_count}/{len(js_links)}] {link} -> Exception: {e}")

    if inline_scripts:
        print(Fore.YELLOW + f"\n[INFO] Found {len(inline_scripts)} inline scripts. Starting scan...")
        for i, script_content in enumerate(inline_scripts):
            source_name = f"Inline Script #{i+1} from {target_url}"
            print(Fore.CYAN + f"\n[Inline {i+1}/{len(inline_scripts)}] Scanning: {source_name}")
            scan_content(source_name, script_content, entropy_threshold, output_file, do_sourcemap=False)

    print_summary(waf_info, output_file)
    _finalize_json(args.json)


def _fetch_and_scan_simple(link, entropy_threshold, output_file, do_sourcemap,
                            delay_min=0.0, delay_max=0.0, retries=3):
    """Fallback fetch+scan for --no-deep-crawl mode."""
    if delay_max > 0:
        time.sleep(random.uniform(delay_min, delay_max))
    try:
        response = request_with_retry(link, timeout=10, retries=retries, base_delay=1.0, rotate_ua=True)
        response.raise_for_status()
        scan_content(link, response.text, entropy_threshold, output_file,
                     do_sourcemap=do_sourcemap, js_url=link)
        return link, True, None
    except requests.exceptions.RequestException as e:
        with RESULTS_LOCK:
            RESULTS["js_files_failed"].append({"url": link, "error": str(e)})
        return link, False, str(e)


def print_summary(waf_info, output_file):
    lines = []
    lines.append("\n" + "=" * 60)
    lines.append("SCAN RESULTS SUMMARY")
    lines.append("=" * 60)
    lines.append(f"Target            : {RESULTS['target']}")

    initial = len(RESULTS['js_files'])
    discovered = len(RESULTS.get('js_files_discovered', []))
    failed = len(RESULTS['js_files_failed'])
    total_scanned = initial + discovered - failed

    lines.append(f"JS files (page)   : {initial}")
    if discovered > 0:
        lines.append(f"JS files (deep crawl): +{discovered} chunks discovered")
    lines.append(f"Total JS scanned  : {total_scanned} ({failed} failed)")
    lines.append(f"Source maps found : {len(RESULTS['source_maps'])}")
    lines.append(f"Unique endpoints  : {len(RESULTS['endpoints'])}")
    if waf_info:
        lines.append(f"WAF detected      : {', '.join(waf_info)} (results may be incomplete)")

    high_findings = [f for f in RESULTS["findings"] if f.get("confidence") == "HIGH"]
    medium_findings = [f for f in RESULTS["findings"] if f.get("confidence") == "MEDIUM"]

    lines.append(f"\n--- SECRET HIGH CONFIDENCE ({len(high_findings)}) — check these first ---")
    if high_findings:
        by_type = {}
        for f in high_findings:
            by_type.setdefault(f["type"], []).append(f)
        for t, items in by_type.items():
            lines.append(f"  [{t}] x{len(items)}")
            for item in items[:5]:
                lines.append(f"    - {item['value']}  (in: {item['source']})")
            if len(items) > 5:
                lines.append(f"    ... and {len(items) - 5} more")
    else:
        lines.append("  (none)")

    lines.append(f"\n--- SECRET MEDIUM CONFIDENCE ({len(medium_findings)}) — needs manual verification ---")
    if medium_findings:
        by_type = {}
        for f in medium_findings:
            by_type.setdefault(f["type"], []).append(f)
        for t, items in by_type.items():
            lines.append(f"  [{t}] x{len(items)}")
    else:
        lines.append("  (none)")

    lines.append(f"\n--- HIGH ENTROPY STRINGS (generic, noise-prone): {len(RESULTS['high_entropy'])} ---")
    lines.append(f"--- BASE64-LIKE STRINGS (generic, noise-prone): {len(RESULTS['suspicious_b64'])} ---")
    lines.append("  (see full JSON/txt output for details on these two categories)")

    lines.append("=" * 60)

    summary_text = "\n".join(lines)
    print(Fore.GREEN + summary_text)

    if output_file:
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write(summary_text + "\n")
        print(Fore.GREEN + f"\n[OK] Full results saved to: {output_file}")


def _finalize_json(json_path):
    if not json_path:
        return
    exportable = dict(RESULTS)
    exportable["endpoints"] = sorted(RESULTS["endpoints"])
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(exportable, f, indent=2, ensure_ascii=False)
    print(Fore.GREEN + f"[OK] JSON results saved to: {json_path}")


if __name__ == "__main__":
    main()
