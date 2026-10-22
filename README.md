<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/version-2.3-green.svg" alt="Version 2.3">
  <img src="https://img.shields.io/badge/license-MIT-yellow.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/purpose-reconnaissance-red.svg" alt="Recon Tool">
</p>

<h1 align="center">&#128373;&#65039; suanggipector</h1>

<p align="center">
  <b>JavaScript Reconnaissance Scanner for Pentest & Bug Bounty</b><br>
  <i>Deep Chunk Discovery &bull; 40+ Secret Patterns &bull; Entropy Analysis &bull; Source Map Reconstruction &bull; AST Sink Extraction &bull; WAF Detection</i>
</p>

<p align="center">
  &#128269; Finds what other scanners miss — lazy-loaded chunks, dynamic imports, deeply nested JS bundles, and reconstructed source maps.
</p>

---

## &#128373;&#65039; Overview

**suanggipector** is a modular Python-based JavaScript reconnaissance tool built for penetration testers and bug bounty hunters. It crawls a target website, discovers all JavaScript files — including deeply nested chunks from Nuxt.js, Webpack, and Vite — and scans them for leaked secrets, API keys, endpoints, and sensitive data.

### What's New in v2.3

- **Modular architecture** — Clean separation into `core/` (engine) and `modules/` (features) for maintainability
- **Source Map v3 Reconstruction** — Downloads `.js.map` files and reconstructs original source trees with full path-traversal sanitization
- **Tree-sitter AST Analysis** — Parses JavaScript AST to extract network sinks (`fetch`, `axios`, `XMLHttpRequest`) and API route literals
- **New CLI flags** — `--extract-sourcemaps`, `--ast-analysis`, `--output-json`
- **Full backward compatibility** — All v2.2 flags and behavior preserved

---

## &#127775; Architecture

```
suanggipector/
├── core/                      # Core scanning engine
│   ├── __init__.py
│   ├── crawler.py             # BFS chunk discovery & HTTP engine
│   ├── entropy.py             # Shannon entropy calculator & string heuristics
│   └── rules.py               # Secret patterns, signatures, and regex engine
├── modules/                   # Feature modules
│   ├── __init__.py
│   ├── sourcemap.py           # Source Map detection, download, safe reconstruction
│   └── ast_analyzer.py        # Tree-sitter AST parser for sink extraction
├── tests/
│   ├── __init__.py
│   └── test_analyzer.py       # Unit tests for AST parsing, entropy, sanitization
├── suanggipector.py           # CLI entrypoint (argparse orchestrator)
├── requirements.txt           # Dependencies
└── README.md
```

---

## &#127775; Key Features

### &#128375;&#65039; Deep JS Chunk Discovery (BFS)
- **Breadth-First Search crawl** — recursively discovers JS files referenced inside other JS files
- Finds `_nuxt/` chunks, Webpack dynamic imports, Vite lazy chunks, and more
- Configurable crawl depth (`--crawl-depth`) and max file limits (`--max-js-files`)
- Follows same-origin references only (no cross-domain leakage)

### &#128272; 40+ Provider-Specific Secret Patterns

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

### &#128506;&#65039; Source Map Reconstruction (v2.3 NEW)
- Detects `sourceMappingURL` comments in JS files
- Downloads and parses Source Map v3 JSON
- **Reconstructs original source files** into a local directory
- **Path traversal protection**: strips `webpack:///`, `vite:///`, `../` sequences, and validates `os.path.abspath` stays within output directory
- Enable with `--extract-sourcemaps`

### &#129504; AST Sink Extraction (v2.3 NEW)
- **Tree-sitter** JavaScript parser (modern API >= 0.22.x)
- Extracts network sinks: `fetch()`, `axios()`, `axios.get/post/put/delete()`
- Detects `XMLHttpRequest.open()` calls
- API route literal extraction via pattern matching: `/api/v1/*`, `/graphql`, `/admin/*`, `/auth/*`, etc.
- Enable with `--ast-analysis`

### &#127922; Entropy Analysis
- **Shannon Entropy** calculation for detecting high-entropy strings
- Configurable threshold (default: 5.0)
- Separate Base64-like string detection
- 40+ false-positive hints to filter build noise

### &#128737;&#65039; WAF Detection
Detects 10+ Web Application Firewalls: Cloudflare, AWS WAF, Akamai, Imperva, Sucuri, F5 BIG-IP, Fortinet, Barracuda, ModSecurity, Wordfence.

### &#9889; Performance & Stealth
- **ThreadPoolExecutor** for parallel JS file fetching
- **User-Agent rotation** across 4 realistic browser UA strings
- **Exponential backoff** with jitter on rate limits (429/503)
- Configurable request delays for stealth scanning

---

## &#128640; Installation

```bash
git clone https://github.com/suanggiLaut/suanggipector.git
cd suanggipector
pip install -r requirements.txt
```

### Requirements
- Python 3.10+
- `requests` — HTTP requests
- `beautifulsoup4` — HTML parsing
- `colorama` — Colored terminal output
- `tree-sitter` — AST parsing engine (optional, for `--ast-analysis`)
- `tree-sitter-javascript` — JavaScript grammar for tree-sitter

---

## &#128373;&#65039; Usage

### Basic Scan (backward compatible with v2.2)
```bash
python suanggipector.py -u https://target.com
```

### Full v2.3 Scan
```bash
python suanggipector.py -u https://target.com \
    --extract-sourcemaps \
    --ast-analysis \
    --output-json results.json \
    -o results.txt
```

### Source Map Reconstruction Only
```bash
python suanggipector.py -u https://target.com \
    --extract-sourcemaps \
    --sourcemap-output ./reconstructed_sources
```

### AST Sink Extraction
```bash
python suanggipector.py -u https://target.com \
    --ast-analysis \
    --output-json ast_results.json
```

### Full Options Example
```bash
python suanggipector.py -u https://target.com \
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
    --ast-analysis
```

### Disable Specific Features
```bash
# No deep chunk discovery
python suanggipector.py -u https://target.com --no-deep-crawl

# No entropy scanning
python suanggipector.py -u https://target.com --no-entropy

# No source map discovery
python suanggipector.py -u https://target.com --no-sourcemap
```

### Stealth Mode
```bash
python suanggipector.py -u https://target.com \
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
| `--json` | Save results to JSON file (v2.2 compat) | — |
| `--output-json` | Save results to JSON file (v2.3) | — |
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
| **v2.3 NEW** | | |
| `--extract-sourcemaps` | Download & reconstruct source files from .js.map | `false` |
| `--sourcemap-output` | Output directory for reconstructed sources | `sourcemaps_out` |
| `--ast-analysis` | Enable Tree-sitter AST sink extraction | `false` |

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
  ]
}
```

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
&#128269; BFS Deep Crawl
 |── Depth 1-N: Fetch JS files, extract references, repeat
 |
 v
&#128375;&#65039; Scan ALL Discovered JS Files
 |── 40+ regex patterns (secrets, keys, tokens)
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
python -m unittest tests.test_analyzer -v
```

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
