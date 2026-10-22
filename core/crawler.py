#!/usr/bin/env python3
"""
suanggipector.core.crawler
~~~~~~~~~~~~~~~~~~~~~~~~~~
BFS deep chunk discovery engine, HTTP retry logic with UA rotation,
WAF detection, and HTML script/link extraction.
"""

import re
import time
import random
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import Fore

from .rules import USER_AGENTS

# ---------------------------------------------------------------------------
# Deep JS chunk discovery — regex patterns for referenced JS files
# ---------------------------------------------------------------------------
_JS_CHUNK_PATTERNS = [
    # Direct path references: "/_nuxt/BxAbCd.js"
    re.compile(r'''["'`](/_nuxt/[A-Za-z0-9_.$-]+\.(?:js|mjs))["'`]'''),
    # Webpack/Vite chunk loading filename
    re.compile(r'''["'`]([A-Za-z0-9_$-]{4,}\.(?:js|mjs))["'`]'''),
    # Dynamic import() with string literal path
    re.compile(r'''import\s*\(\s*["'`](\.?/[^"'`]+\.(?:js|mjs))["'`]\s*\)'''),
    # Relative JS references: "./path/file.js"
    re.compile(r'''["'`](\./[A-Za-z0-9_./-]+\.(?:js|mjs))["'`]'''),
    # Full URL references to same-origin JS
    re.compile(r'''["'`](https?://[^"'`\s]+\.(?:js|mjs))["'`]'''),
]

# Patterns to SKIP when discovering chunks
_CHUNK_SKIP_PATTERNS = re.compile(
    r'(?:'
    r'node_modules|\.min\.js$|sourceMappingURL|'
    r'webpack\.runtime|hot-update|\.map$|'
    r'example\.(?:com|org|net)|localhost'
    r')',
    re.IGNORECASE,
)


def request_with_retry(url, headers=None, timeout=15, retries=3,
                        base_delay=1.0, rotate_ua=True):
    """GET with retry + exponential backoff + optional UA rotation."""
    last_exc = None
    for attempt in range(1, retries + 1):
        req_headers = dict(headers or {})
        if rotate_ua:
            req_headers['User-Agent'] = random.choice(USER_AGENTS)
        try:
            resp = requests.get(
                url, headers=req_headers, timeout=timeout, verify=False
            )
            if resp.status_code in (429, 503):
                wait = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 0.5)
                print(
                    Fore.YELLOW +
                    f"[RATE LIMIT] {url} -> HTTP {resp.status_code}, "
                    f"waiting {wait:.1f}s (attempt {attempt}/{retries})"
                )
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


def extract_js_refs_from_content(js_content, base_url):
    """
    Extract references to other JS files from within a JS file's content.
    Returns a set of absolute URLs.
    """
    found = set()
    parsed_base = urlparse(base_url)
    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    for pattern in _JS_CHUNK_PATTERNS:
        for match in pattern.finditer(js_content):
            ref = match.group(1)
            if _CHUNK_SKIP_PATTERNS.search(ref):
                continue
            basename = ref.rsplit('/', 1)[-1] if '/' in ref else ref
            if len(basename) < 4:
                continue

            if ref.startswith('http://') or ref.startswith('https://'):
                ref_parsed = urlparse(ref)
                if ref_parsed.netloc == parsed_base.netloc:
                    found.add(ref)
            elif ref.startswith('/'):
                found.add(base_origin + ref)
            elif ref.startswith('./') or ref.startswith('../'):
                found.add(urljoin(base_url, ref))
            else:
                js_dir = base_url.rsplit('/', 1)[0] + '/'
                found.add(js_dir + ref)

    return found


def deep_discover_js_chunks(initial_js_urls, base_target_url, concurrency=8,
                             delay_min=0.0, delay_max=0.0, retries=3,
                             max_depth=3, max_files=200):
    """
    BFS crawl: fetch JS files, extract references to other JS files,
    repeat until no new files or limits are reached.

    Returns:
        (fetched_map, failed_set) — url->content dict, and set of failed URLs
    """
    parsed_target = urlparse(base_target_url)
    target_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"

    fetched = {}
    failed = set()
    queue = set(initial_js_urls)
    all_known = set(initial_js_urls)

    depth = 0
    while queue and depth < max_depth and len(fetched) < max_files:
        depth += 1
        batch = list(queue)
        queue = set()

        print(
            Fore.YELLOW +
            f"\n[DEEP CRAWL] Depth {depth}: fetching {len(batch)} JS files..."
        )

        def _fetch_one(url):
            if delay_max > 0:
                time.sleep(random.uniform(delay_min, delay_max))
            try:
                resp = request_with_retry(
                    url, timeout=10, retries=retries,
                    base_delay=1.0, rotate_ua=True,
                )
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
                    new_refs = extract_js_refs_from_content(content, url)
                    for ref_url in new_refs:
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
            print(
                Fore.YELLOW +
                f"[DEEP CRAWL] Discovered {len(queue)} new JS chunks to scan..."
            )

    total = len(fetched)
    discovered = total - len(initial_js_urls & set(fetched.keys()))
    if discovered > 0:
        print(
            Fore.GREEN +
            f"[DEEP CRAWL] Total: {total} JS files "
            f"({discovered} extra chunks discovered via deep crawl)"
        )
    else:
        print(
            Fore.YELLOW +
            f"[DEEP CRAWL] No additional chunks discovered beyond "
            f"initial {len(initial_js_urls)} files."
        )

    return fetched, failed


def detect_waf(response):
    """Detect WAF from HTTP response headers."""
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
    header_keys_lower = [k.lower() for k in response.headers.keys()]

    for waf_name, signatures in waf_signatures.items():
        for sig in signatures:
            if sig.lower() in header_keys_lower:
                detected_wafs.append(waf_name)
                break

    if response.status_code == 403:
        body_lower = response.text.lower()
        if 'request blocked' in body_lower or 'access denied' in body_lower:
            if 'Cloudflare' not in detected_wafs:
                detected_wafs.append('Generic WAF (403 Block)')

    if response.status_code == 406:
        detected_wafs.append('Possible WAF (406 Not Acceptable)')

    return list(set(detected_wafs))


def get_scripts(url, output_file=None, results=None):
    """Extract external JS file URLs and inline script content from target."""
    print(Fore.YELLOW + f"[INFO] Crawling target: {url}")
    print(
        Fore.RED +
        "[WARNING] verify=False -- SSL certificate not validated. "
        "Use for testing only!"
    )

    js_files = set()
    inline_scripts = []
    detected_waf = None

    try:
        response = request_with_retry(
            url, timeout=15, retries=3, base_delay=1.0, rotate_ua=True
        )
        detected_waf = detect_waf(response)
        if detected_waf:
            print(Fore.RED + f"[WAF DETECTED] Detected: {', '.join(detected_waf)}")
            if results is not None:
                results["waf_detected"] = detected_waf
            if output_file:
                with open(output_file, 'a', encoding='utf-8') as f:
                    f.write(f"\n[WAF DETECTED] {', '.join(detected_waf)} at {url}\n")
        else:
            print(Fore.GREEN + "[OK] No WAF detected from response headers.")

        response.raise_for_status()
        html_text = response.text
        soup = BeautifulSoup(html_text, 'html.parser')

        for script_tag in soup.find_all('script', src=True):
            full_url = urljoin(url, script_tag.get('src'))
            js_files.add(full_url)

        for link_tag in soup.find_all('link', rel=True):
            rel = ' '.join(link_tag.get('rel', []))
            href = link_tag.get('href', '')
            if ('preload' in rel or 'prefetch' in rel or 'modulepreload' in rel):
                if href.endswith('.js') or href.endswith('.mjs'):
                    js_files.add(urljoin(url, href))

        for script_tag in soup.find_all('script', src=False):
            if script_tag.string:
                inline_scripts.append(script_tag.string)
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
