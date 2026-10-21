<p align="center">
  <img src="https://img.shields.io/badge/python-3.7+-blue.svg" alt="Python 3.7+">
  <img src="https://img.shields.io/badge/version-2.2-green.svg" alt="Version 2.2">
  <img src="https://img.shields.io/badge/license-MIT-yellow.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/purpose-reconnaissance-red.svg" alt="Recon Tool">
</p>

<h1 align="center">&#128373;&#65039; suanggipector</h1>

<p align="center">
  <b>JavaScript Reconnaissance Scanner for Pentest & Bug Bounty</b><br>
  <i>Deep Chunk Discovery &bull; 40+ Secret Patterns &bull; Entropy Analysis &bull; Source Map Discovery &bull; WAF Detection</i>
</p>

<p align="center">
  &#128269; Finds what other scanners miss — lazy-loaded chunks, dynamic imports, and deeply nested JS bundles.
</p>

---

## &#128373;&#65039; Overview

**suanggipector** is a Python-based JavaScript reconnaissance tool built for penetration testers and bug bounty hunters. It crawls a target website, discovers all JavaScript files — including deeply nested chunks from Nuxt.js, Webpack, and Vite — and scans them for leaked secrets, API keys, endpoints, and sensitive data.

Unlike basic JS scanners that only check `<script>` tags, suanggipector uses **BFS deep chunk discovery** to recursively find and scan every JS file referenced inside other JS files. This catches lazy-loaded chunks, dynamic imports, and framework-specific bundles that are invisible to surface-level scanning.

## &#127775; Key Features

### &#128375;&#65039; Deep JS Chunk Discovery (v2.2)
- **BFS (Breadth-First Search) crawl** — recursively discovers JS files referenced inside other JS files
- Finds `_nuxt/` chunks, Webpack dynamic imports, Vite lazy chunks, and more
- Configurable crawl depth and max file limits
- Follows same-origin references only (no cross-domain leakage)
- Discovers JS files from:
  - `<script src="...">` tags
  - `<link rel="preload/prefetch/modulepreload">` tags
  - Inline `<script>` blocks (Webpack manifests, etc.)
  - References inside JS files themselves (chunk loading patterns)

### &#128272; 40+ Provider-Specific Secret Patterns
Organized by category with HIGH/MEDIUM confidence classification:

| Category | Patterns |
|----------|----------|
| &#9729;&#65039; **Cloud Providers** | Google API Key, Google OAuth, GCP Service Account, AWS Access Key, AWS Secret Key, Azure Storage Key, Azure Client Secret |
| &#128293; **Firebase** | Firebase URL, Firebase Cloud Messaging |
| &#128187; **Code Hosting / CI** | GitHub Token (classic, fine-grained, other, app), GitLab Token, Bitbucket App Password |
| &#128172; **Communication** | Slack Token, Slack Webhook, Discord Bot Token, Discord Webhook, Telegram Bot Token, Microsoft Teams Webhook |
| &#128179; **Payment / Fintech** | Stripe Key, Square Access Token, Square OAuth Secret, PayPal Braintree Token, Shopify Token, Shopify Shared Secret |
| &#9993;&#65039; **Email / Messaging SaaS** | Twilio API Key, Twilio Account SID, SendGrid API Key, Mailgun API Key, Mailchimp API Key, Postmark Token |
| &#128200; **Monitoring** | Datadog API Key, New Relic Key, New Relic Insights Key, Sentry DSN, PagerDuty Key |
| &#127760; **CDN / Hosting** | Cloudflare API Key/Token, DigitalOcean Token, Heroku API Key, Vercel Token, Netlify Token |
| &#128270; **Search / Maps** | Algolia API Key, Mapbox Token |
| &#128230; **Package Registries** | npm Token, PyPI Token, NuGet API Key, RubyGems Token |
| &#128274; **Auth / General** | JWT, Bearer Token, Private Key Header, OAuth Client Secret, Basic Auth Embedded, Generic API Key/Secret |

### &#127922; Entropy Analysis
- **Shannon Entropy** calculation for detecting high-entropy strings (potential secrets)
- Configurable threshold (default: 5.0)
- Separate **Base64-like string** detection

### &#128506;&#65039; Source Map Discovery
- Automatic `.js.map` detection from `sourceMappingURL` comments
- Parses source map JSON to list original source files
- Reveals internal file paths and project structure

### &#128737;&#65039; WAF Detection
Detects 10+ Web Application Firewalls from HTTP response headers:

| WAF | Detection Method |
|-----|-----------------|
| Cloudflare | `cf-ray`, `cf-cache-status` |
| AWS WAF | `x-amzn-requestid`, `x-amz-cf-id` |
| Akamai | `x-akamai-transformed` |
| Imperva | `x-iinfo`, `x-cdn` |
| Sucuri | `x-sucuri-id` |
| F5 BIG-IP | `x-wa-info` |
| Fortinet | `x-fortigate` |
| Barracuda | `x-barracuda` |
| ModSecurity | `x-mod-security` |
| Wordfence | `x-wordfence` |

### &#128683; False Positive Reduction
- **40+ false positive hints** to filter out Webpack/build artifacts, data URIs, JS prototype methods
- Short hex string filter (< 32 chars)
- Static asset noise endpoint filter (`.css`, `.png`, `.svg`, etc.)
- Character diversity check (rejects low-diversity strings)

### &#9889; Performance & Stealth
- **ThreadPoolExecutor** for parallel JS file fetching and scanning
- **User-Agent rotation** across 4 realistic browser UA strings
- **Exponential backoff** with jitter on rate limits (429/503)
- Configurable request delays for stealth scanning
- Thread-safe result aggregation

---

## &#128640; Installation

```bash
git clone https://github.com/suanggiLaut/suanggipector.git
cd suanggipector
pip install -r requirements.txt
```

### Requirements
- Python 3.7+
- `requests` — HTTP requests
- `beautifulsoup4` — HTML parsing
- `colorama` — Colored terminal output

---

## &#128373;&#65039; Usage

### Basic Scan
```bash
python suanggipector.py -u https://target.com
```

### Save Results to File
```bash
python suanggipector.py -u https://target.com -o results.txt --json results.json
```

### Full Options Example
```bash
python suanggipector.py -u https://target.com \
    -o results.txt \
    --json results.json \
    -e 4.5 \
    -c 10 \
    --crawl-depth 5 \
    --max-js-files 300 \
    --delay-min 0.5 \
    --delay-max 2.0 \
    --retries 5
```

### Disable Specific Features
```bash
# Scan without deep chunk discovery (only <script> tags)
python suanggipector.py -u https://target.com --no-deep-crawl

# Disable entropy scanning
python suanggipector.py -u https://target.com --no-entropy

# Disable source map discovery
python suanggipector.py -u https://target.com --no-sourcemap
```

### Stealth Mode (slow & quiet)
```bash
python suanggipector.py -u https://target.com \
    --delay-min 1.0 \
    --delay-max 3.0 \
    -c 2 \
    --retries 5
```

---

## &#128203; CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u`, `--url` | Target URL to scan **(required)** | — |
| `-o`, `--output` | Save output to .txt file | — |
| `--json` | Save structured results to JSON file | — |
| `-e`, `--entropy` | Shannon Entropy threshold | `5.0` |
| `--no-entropy` | Disable entropy scanning | `false` |
| `--no-sourcemap` | Disable source map discovery | `false` |
| `--no-deep-crawl` | Disable deep JS chunk discovery | `false` |
| `--crawl-depth` | Maximum BFS crawl depth | `3` |
| `--max-js-files` | Maximum JS files to scan | `200` |
| `-c`, `--concurrency` | Parallel worker threads | `8` |
| `--delay-min` | Min delay before each request (sec) | `0.0` |
| `--delay-max` | Max delay before each request (sec) | `0.0` |
| `--retries` | Retry count with exponential backoff | `3` |

---

## &#128196; Output Format

### Terminal Output
Color-coded output with:
- &#9989; Findings grouped by JS file source
- &#128308; Confidence labels: `[HIGH]` / `[MEDIUM]`
- &#128274; Masked sensitive values (first 4 + last 4 chars)
- &#128209; Deep crawl progress with depth indicators
- &#128202; Summary table at the end

### JSON Output (`--json`)
```json
{
  "target": "https://target.com",
  "waf_detected": ["Cloudflare"],
  "js_files": ["https://target.com/main.js"],
  "js_files_discovered": ["https://target.com/_nuxt/chunk-abc.js"],
  "js_files_failed": [],
  "source_maps": [],
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
  "suspicious_b64": []
}
```

---

## &#129504; How Deep Chunk Discovery Works

```
&#128373;&#65039; Target HTML Page
 |
 |── Extract <script src="..."> tags
 |── Extract <link rel="preload/prefetch/modulepreload"> JS links
 |── Extract JS references from inline <script> blocks
 |
 v
&#128269; BFS Deep Crawl (enabled by default)
 |
 |── Depth 1: Fetch initial JS files
 |   └── Extract JS references from content (_nuxt/, imports, etc.)
 |
 |── Depth 2: Fetch newly discovered JS files
 |   └── Extract more references...
 |
 |── Depth N: Repeat until no new files or limits reached
 |
 v
&#128375;&#65039; Scan ALL Discovered JS Files
 |
 |── 40+ regex patterns (secrets, keys, tokens)
 |── URL endpoint extraction
 |── Shannon entropy analysis
 |── Base64-like string detection
 └── Source map discovery
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
