<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/version-2.7-green.svg" alt="Version 2.7">
  <img src="https://img.shields.io/badge/license-MIT-yellow.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/purpose-reconnaissance-red.svg" alt="Recon Tool">
</p>

<h1 align="center">&#128373;&#65039; suanggipector</h1>

<p align="center">
  <b>JavaScript Reconnaissance Scanner for Pentest & Bug Bounty</b><br>
  <i>Deep Chunk Discovery &bull; 56 Secret Patterns &bull; Entropy Analysis &bull; Source Map Reconstruction &bull; AST Sink Extraction &bull; WAF Detection &bull; Framework Intelligence &bull; Proxy &amp; Auth Support</i>
</p>

<p align="center">
  &#128269; Finds what other scanners miss — lazy-loaded chunks, dynamic imports, deeply nested JS bundles, reconstructed source maps, and framework-specific attack surfaces.
</p>

---

## &#128373;&#65039; Overview

**suanggipector** is a modular Python-based JavaScript reconnaissance tool built for penetration testers and bug bounty hunters. It crawls a target website, discovers all JavaScript files — including deeply nested chunks from Nuxt.js, Webpack, and Vite — and scans them for leaked secrets, API keys, endpoints, and sensitive data.

### What's New in v2.7.1 — Hardened & Extended

**New Features:**
- **Proxy Support** — Route all traffic through HTTP or SOCKS5 proxies (`--proxy`)
- **Authenticated Scanning** — Inject custom headers (`--header`) and cookies (`--cookie`) into every request
- **Severity Filter** — Show only HIGH confidence findings in console output (`--severity-filter high`), while still saving everything to JSON/txt
- **CI/CD Exit Codes** — Exit code `1` when HIGH confidence secrets or Laravel `.env` exposure are found, `0` when clean, `2` on error

**Security Hardening:**
- **SSRF Protection** — Private/internal IP detection with `--block-internal` to prevent server-side request forgery
- **URL Scheme Validation** — Blocks non-HTTP(S) schemes (`file://`, `javascript:`, etc.)
- **Cross-Domain Redirect Detection** — Warns when responses redirect to a different domain
- **Path Traversal Protection** — Source map reconstruction sanitizes `../` sequences and validates output stays within the target directory
- **Secret Masking** — All secret values are masked in console and text output (`AIza***XyZ1`)
- **Pinned Dependencies** — `requirements.txt` uses exact versions to prevent supply chain issues

**Bug Fixes:**
- Fixed GitHub token regex overlap between "GitHub Token (other)" and "GitHub App Token" patterns
- Fixed false-positive noise filtering for high-entropy string detection
- Fixed `--json` flag deprecation (now shows warning, use `--output-json` instead)
- Corrected Nuxt.js description — fingerprint-only, no active probes

**Quality:**
- **189 unit tests** across 7 test files with full coverage of all modules
- Consistent code style and docstrings across all modules

### Previous Releases

<details>
<summary><b>v2.7 — Framework-Specific Intelligence</b></summary>

- **Framework Fingerprinting** — Detects 12+ frameworks (Next.js, Nuxt.js, WordPress, Laravel, Angular, Vite, React, Gatsby, Svelte, Vue, Express, etc.)
- **Next.js Recon** — buildId extraction, `/_next/data/` probing, API route discovery
- **WordPress REST API Enumeration** — User enum, namespace discovery, debug.log, config backup check
- **Laravel Debug Mode Detection** — `.env` exposure, Ignition/Whoops, Telescope/Horizon
- New CLI flags: `--framework-detect`, `--no-framework-probe`

</details>

<details>
<summary><b>v2.3 — Modular Architecture & Source Map Recon</b></summary>

- Modular architecture — Clean separation into `core/` (engine) and `modules/` (features)
- Source Map v3 Reconstruction with path-traversal sanitization
- Tree-sitter AST Analysis for sink extraction
- New CLI flags: `--extract-sourcemaps`, `--ast-analysis`, `--output-json`

</details>

---

## &#127775; Architecture

```
suanggipector/
├── core/                      # Core scanning engine
│   ├── __init__.py
│   ├── crawler.py             # BFS chunk discovery, HTTP engine, SSRF protection
│   ├── entropy.py             # Shannon entropy calculator & string heuristics
│   └── rules.py               # 56 secret patterns, signatures, and regex engine
├── modules/                   # Feature modules
│   ├── __init__.py
│   ├── sourcemap.py           # Source Map detection, download, safe reconstruction
│   ├── ast_analyzer.py        # Tree-sitter AST parser for sink extraction
│   └── framework.py           # Framework fingerprinting & specific intelligence
├── tests/                     # 189 unit tests
│   ├── __init__.py
│   ├── test_analyzer.py       # Entropy, sanitization, regex, AST (36 tests)
│   ├── test_framework.py      # Framework fingerprinting, detection (28 tests)
│   ├── test_crawler.py        # URL validation, SSRF, WAF, BFS, proxy, headers (47 tests)
│   ├── test_scan.py           # Regex matching, entropy, b64, severity filter (23 tests)
│   ├── test_sourcemap_recon.py  # Source map discovery & reconstruction (15 tests)
│   └── test_framework_probes.py # Framework-specific probing (20 tests)
├── suanggipector.py           # CLI entrypoint (argparse orchestrator)
├── pyproject.toml             # Package metadata (pip install -e .)
├── requirements.txt           # Pinned dependencies
└── README.md
```

---

## &#127775; Key Features

### &#128375;&#65039; Deep JS Chunk Discovery (BFS)
- **Breadth-First Search crawl** — recursively discovers JS files referenced inside other JS files
- Finds `_nuxt/` chunks, Webpack dynamic imports, Vite lazy chunks, and more
- Configurable crawl depth (`--crawl-depth`) and max file limits (`--max-js-files`)
- Follows same-origin references only (no cross-domain leakage)

### &#128272; 56 Provider-Specific Secret Patterns

| Category | Patterns |
|----------|----------|
| &#9729;&#65039; **Cloud** | Google API Key, Google OAuth, GCP SA, AWS Access/Secret Key, Azure Storage/Client Secret |
| &#128293; **Firebase** | Firebase URL, Firebase Cloud Messaging |
| &#128187; **Code/CI** | GitHub Token (classic, fine-grained, app), GitLab Token, Bitbucket App Password |
| &#128172; **Chat** | Slack Token/Webhook, Discord Bot/Webhook, Telegram Bot, Teams Webhook |
| &#128179; **Payment** | Stripe Key, Square Token/OAuth, PayPal Braintree, Shopify Token/Secret |
| &#9993;&#65039; **Email** | Twilio API/SID, SendGrid, Mailgun, Mailchimp, Postmark |
| &#128200; **Monitoring** | Datadog, New Relic, Sentry DSN, PagerDuty |
| &#127760; **CDN/Hosting** | Cloudflare API, DigitalOcean, Heroku, Vercel, Netlify |
| &#128270; **Search/Maps** | Algolia, Mapbox |
| &#128230; **Package** | npm, PyPI, NuGet, RubyGems |
| &#128274; **Auth** | JWT, Bearer Token, Private Key, OAuth Secret, Basic Auth, Generic API Key |

### &#128506;&#65039; Source Map Reconstruction
- Detects `sourceMappingURL` comments in JS files
- Downloads and parses Source Map v3 JSON
- **Reconstructs original source files** into a local directory
- **Path traversal protection**: strips `webpack:///`, `vite:///`, `../` sequences, and validates output stays within the target directory
- Configurable max download size and file count limits
- Enable with `--extract-sourcemaps`

### &#129504; AST Sink Extraction
- **Tree-sitter** JavaScript parser (modern API >= 0.22.x)
- Extracts network sinks: `fetch()`, `axios()`, `axios.get/post/put/delete()`
- Detects `XMLHttpRequest.open()` calls
- API route literal extraction via pattern matching: `/api/v1/*`, `/graphql`, `/admin/*`, `/auth/*`, etc.
- Enable with `--ast-analysis`

### &#128268; Framework-Specific Intelligence

Automatically detects the target's tech stack and runs framework-specific recon:

| Framework | Detection | Active Probes |
|-----------|-----------|---------------|
| **Next.js** | `__NEXT_DATA__`, `/_next/static/`, `x-powered-by` header, `x-nextjs-cache` header | `buildId` extraction, `/_next/data/` endpoint probing, API route discovery (`/api/auth/*`, `/api/health`) |
| **Nuxt.js** | `__NUXT__`, `/_nuxt/` script tags | — (fingerprint only) |
| **WordPress** | `/wp-content/`, `/wp-includes/`, generator meta, `Link` header | User enumeration (`/wp-json/wp/v2/users`), REST namespace discovery, `xmlrpc.php`, `debug.log`, `readme.html`, config backup check |
| **Laravel** | CSRF meta token, `x-powered-by` header, Laravel Mix assets | `.env` exposure (with key extraction), Ignition health check, Telescope/Horizon dashboard, storage log access |
| **Angular** | `<app-root>`, `ng-version` attribute | Version extraction |
| **Vite** | `/@vite/client`, module script tags | HMR client detection |
| **React** | `#root` mount, production bundle reference | Bundle identification |
| **Gatsby** | `___gatsby` root div | — |
| **Svelte** | `__svelte` hydration marker | — |
| **Vue.js** | `#app` mount pattern | — |
| **Express** | `x-powered-by: Express` header | — |
| **Hosting** | Vercel (`x-vercel-id`), Netlify (`x-nf-request-id`) | — |

Enable with `--framework-detect`

### &#127922; Entropy Analysis
- **Shannon Entropy** calculation for detecting high-entropy strings
- Configurable threshold (default: 5.0)
- Separate Base64-like string detection
- 40+ false-positive hints to filter build noise

### &#128737;&#65039; WAF Detection
Detects 10+ Web Application Firewalls: Cloudflare, AWS WAF, Akamai, Imperva, Sucuri, F5 BIG-IP, Fortinet, Barracuda, ModSecurity, Wordfence.

### &#128274; SSRF Protection
- Detects private/internal IPs (RFC 1918, loopback, link-local)
- `--block-internal` mode blocks all requests to private hosts
- Warning mode (default) alerts on private IP resolution without blocking
- URL scheme validation rejects non-HTTP(S) URLs

### &#128247; Proxy & Authenticated Scanning
- **HTTP/SOCKS5 proxy** support via `--proxy` (e.g., `--proxy socks5://127.0.0.1:1080`)
- **Custom headers** via `--header "Name: Value"` (repeatable)
- **Cookie injection** via `--cookie "session=abc123"`
- All headers are sent on every request (crawl, deep scan, probes)

### &#9889; Performance & Stealth
- **ThreadPoolExecutor** for parallel JS file fetching
- **User-Agent rotation** across 4 realistic browser UA strings
- **Exponential backoff** with jitter on rate limits (429/503)
- Configurable request delays for stealth scanning

### &#128736;&#65039; CI/CD Integration
- **Exit code `0`** — scan completed, no high-confidence findings
- **Exit code `1`** — HIGH confidence secrets or Laravel `.env` exposure detected
- **Exit code `2`** — scan error (connection failure, invalid target)
- Use `--output-json` to capture machine-readable results

---

## &#128640; Installation

```bash
git clone https://github.com/suanggiLaut/suanggipector.git
cd suanggipector
pip install -r requirements.txt
```

Or install as a package (run from anywhere):
```bash
pip install -e .
suanggipector -u https://target.com
```

### Requirements
- Python 3.10+
- `requests==2.34.2` — HTTP requests
- `beautifulsoup4==4.15.0` — HTML parsing
- `colorama==0.4.6` — Colored terminal output
- `tree-sitter>=0.22.0` — AST parsing engine (optional, for `--ast-analysis`)
- `tree-sitter-javascript>=0.23.0` — JavaScript grammar for tree-sitter

---

## &#128373;&#65039; Usage

### Basic Scan
```bash
suanggipector -u https://target.com
```

### Full Scan (all features)
```bash
suanggipector -u https://target.com \
    --framework-detect \
    --extract-sourcemaps \
    --ast-analysis \
    --output-json results.json \
    -o results.txt
```

### Scan Through a Proxy
```bash
suanggipector -u https://target.com \
    --proxy http://127.0.0.1:8080

# SOCKS5 proxy (e.g., Tor)
suanggipector -u https://target.com \
    --proxy socks5://127.0.0.1:9050
```

### Authenticated Scan (with cookies/headers)
```bash
suanggipector -u https://target.com \
    --cookie "session=abc123; token=xyz" \
    --header "Authorization: Bearer eyJhbGci..." \
    --header "X-API-Key: my-key"
```

### Show Only HIGH Confidence Findings
```bash
suanggipector -u https://target.com \
    --severity-filter high \
    --output-json results.json
```
> Console shows only HIGH confidence findings. All findings (HIGH + MEDIUM) are still saved in JSON/txt output.

### CI/CD Pipeline
```bash
suanggipector -u https://target.com \
    --output-json results.json \
    --severity-filter high

# Exit code: 0 = clean, 1 = findings, 2 = error
if [ $? -eq 1 ]; then
    echo "ALERT: Secrets detected!"
    # notify team / fail pipeline
fi
```

### Framework Detection Only
```bash
suanggipector -u https://target.com \
    --framework-detect \
    --output-json results.json
```

### Framework Fingerprint Only (no active probing)
```bash
suanggipector -u https://target.com \
    --framework-detect \
    --no-framework-probe
```

### Source Map Reconstruction
```bash
suanggipector -u https://target.com \
    --extract-sourcemaps \
    --sourcemap-output ./reconstructed_sources
```

### AST Sink Extraction
```bash
suanggipector -u https://target.com \
    --ast-analysis \
    --output-json ast_results.json
```

### Full Options Example
```bash
suanggipector -u https://target.com \
    -o results.txt \
    --output-json results.json \
    -e 4.5 \
    -c 10 \
    --crawl-depth 5 \
    --max-js-files 300 \
    --delay-min 0.5 \
    --delay-max 2.0 \
    --retries 5 \
    --extract-sourcemaps \
    --sourcemap-output ./src_recon \
    --ast-analysis \
    --framework-detect \
    --proxy http://127.0.0.1:8080 \
    --cookie "session=abc123" \
    --header "Authorization: Bearer tok" \
    --severity-filter high
```

### Disable Specific Features
```bash
# No deep chunk discovery
suanggipector -u https://target.com --no-deep-crawl

# No entropy scanning
suanggipector -u https://target.com --no-entropy

# No source map discovery
suanggipector -u https://target.com --no-sourcemap
```

### Stealth Mode
```bash
suanggipector -u https://target.com \
    --delay-min 1.0 \
    --delay-max 3.0 \
    -c 2
```

---

## &#128203; CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u`, `--url` | Target URL to scan **(required)** | — |
| `-o`, `--output` | Save output to .txt file | — |
| `--output-json` | Save results to JSON file | — |
| `--json` | *(deprecated, use `--output-json`)* | — |
| `-e`, `--entropy` | Shannon Entropy threshold | `5.0` |
| `--no-entropy` | Disable entropy scanning | `false` |
| `--no-sourcemap` | Disable source map discovery | `false` |
| `--no-deep-crawl` | Disable deep chunk discovery | `false` |
| `--crawl-depth` | Maximum BFS crawl depth | `3` |
| `--max-js-files` | Maximum JS files to scan | `200` |
| `-c`, `--concurrency` | Parallel worker threads | `8` |
| `--delay-min` | Min delay before each request (sec) | `0.0` |
| `--delay-max` | Max delay before each request (sec) | `0.0` |
| `--retries` | Retry count with exponential backoff | `3` |
| `--verify-ssl` | Enable SSL certificate verification | `false` |
| `--block-internal` | Block requests to private/internal IPs (SSRF protection) | `false` |
| `--extract-sourcemaps` | Download & reconstruct source files from .js.map | `false` |
| `--sourcemap-output` | Output directory for reconstructed sources | `sourcemaps_out` |
| `--max-sourcemap-files` | Max files per source map to reconstruct | `50` |
| `--ast-analysis` | Enable Tree-sitter AST sink extraction | `false` |
| `--framework-detect` | Enable framework fingerprinting & specific recon | `false` |
| `--no-framework-probe` | Fingerprint only — skip active probing | `false` |
| **New in v2.7.1** | | |
| `--proxy` | HTTP or SOCKS5 proxy URL | — |
| `--cookie` | Cookie string to send with every request | — |
| `--header` | Custom header `"Name: Value"` (repeatable) | — |
| `--severity-filter` | Console output filter: `all` or `high` | `all` |

---

## &#128196; Output Format

### JSON Output (`--output-json`)
```json
{
  "target": "https://target.com",
  "waf_detected": ["Cloudflare"],
  "js_files": ["https://target.com/main.js"],
  "js_files_discovered": ["https://target.com/_nuxt/chunk-abc.js"],
  "js_files_failed": [],
  "source_maps": [],
  "source_maps_reconstructed": [
    {
      "js_file": "https://target.com/main.js",
      "map_url": "https://target.com/main.js.map",
      "files_written": ["src/App.js", "src/utils/api.js"],
      "files_skipped": []
    }
  ],
  "endpoints": ["/api/v1/users", "/api/auth/login"],
  "findings": [
    {
      "source": "https://target.com/_nuxt/chunk-abc.js",
      "type": "Google API Key",
      "value": "AIza***XyZ1",
      "confidence": "HIGH"
    }
  ],
  "high_entropy": [],
  "suspicious_b64": [],
  "ast_sinks": [
    {
      "source": "https://target.com/main.js",
      "kind": "fetch_call",
      "value": "/api/v1/data",
      "line": 42
    }
  ],
  "ast_api_routes": [
    {
      "source": "https://target.com/main.js",
      "route": "/api/v1/users",
      "line": 15
    }
  ],
  "framework_intel": {
    "frameworks": [
      {
        "name": "Next.js",
        "version": "abc123buildId",
        "confidence": "HIGH",
        "evidence": ["__NEXT_DATA__ global", "/_next/static/ script tag"]
      }
    ],
    "nextjs_data_routes": [
      {"page": "/", "data_url": "/_next/data/abc123buildId/index.json", "status": 200}
    ],
    "wp_users": [],
    "wp_endpoints": [],
    "laravel_findings": []
  }
}
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed — no high-confidence findings |
| `1` | HIGH confidence secrets or critical exposure detected |
| `2` | Scan error (connection failure, invalid target) |

---

## &#129504; How It Works

```
&#128373;&#65039; Target HTML Page
 |
 |── Extract <script src="..."> tags
 |── Extract <link rel="preload/prefetch/modulepreload">
 |── Extract JS references from inline <script> blocks
 |
 v
&#128268; Framework Detection
 |── Fingerprint from HTML patterns & HTTP headers
 |── Next.js: buildId extraction, _next/data/ probing
 |── WordPress: user enum, REST API discovery
 |── Laravel: .env exposure, debug mode detection
 |
 v
&#128269; BFS Deep Crawl
 |── Depth 1-N: Fetch JS files, extract references, repeat
 |
 v
&#128375;&#65039; Scan ALL Discovered JS Files
 |── 56 regex patterns (secrets, keys, tokens)
 |── URL endpoint extraction
 |── Shannon entropy analysis
 |── Base64-like string detection
 |── Source map discovery & reconstruction (--extract-sourcemaps)
 └── AST sink extraction (--ast-analysis)
     |── fetch() / axios() / XHR calls
     └── API route literals (/api/v1/*, /graphql, etc.)
```

---

## &#129514; Running Tests

```bash
cd suanggipector
python -m pytest tests/ -v
```

Or with unittest:

```bash
python -m unittest discover tests/ -v
```

**Test coverage**: 189 tests across 7 test files:

| File | Tests | Covers |
|------|-------|--------|
| `test_analyzer.py` | 36 | Entropy, noise filters, masking, source map sanitization, AST, regex |
| `test_framework.py` | 28 | Framework fingerprinting, header detection, data classes, merge logic |
| `test_crawler.py` | 47 | URL validation, SSRF, JS refs, WAF, retry, BFS, proxy, extra headers |
| `test_scan.py` | 23 | Regex matching, entropy scanning, base64, severity filter |
| `test_sourcemap_recon.py` | 15 | Source map discovery, reconstruction, path traversal, size limits |
| `test_framework_probes.py` | 20 | Next.js/WordPress/Laravel probes, passive mode |
| **Total** | **189** | |

---

## &#9888;&#65039; Disclaimer

> This tool is intended for **authorized security testing and educational purposes only**.
> Always obtain proper authorization before scanning any target.
> The author is not responsible for any misuse or damage caused by this tool.
> Use responsibly and ethically.

---

## &#128220; License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## &#128100; Author

**suanggiLaut** — [GitHub](https://github.com/suanggiLaut)

---

<p align="center">
  <i>&#128373;&#65039; "The best secrets are the ones you find in JavaScript."</i>
</p>
