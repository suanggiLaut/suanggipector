#!/usr/bin/env python3
"""
suanggipector.core.rules
~~~~~~~~~~~~~~~~~~~~~~~~
Secret-detection regex patterns, confidence classification,
false-positive heuristics, and shared utility helpers.
"""

import re

# ---------------------------------------------------------------------------
# REGEX PATTERNS — provider-specific first, generic last
# ---------------------------------------------------------------------------
REGEX_PATTERNS = {
    # -- URL / Endpoint extraction -----------------------------------------
    'URL Paths': (
        r'''(?:["'`])'''
        r'''('''
            r'''/(?:[a-zA-Z0-9]'''
            r'''[a-zA-Z0-9_./@:~-]*'''
            r'''(?:\?[a-zA-Z0-9_.&=%+-]*)?)'''
        r''')'''
        r'''(?:["'`])'''
    ),

    # -- Cloud provider keys -----------------------------------------------
    'Google API Key':              r'AIza[0-9A-Za-z\-_]{35}',
    'Google OAuth Client ID':      r'[0-9]{5,30}-[a-z0-9_]{28,64}\.apps\.googleusercontent\.com',
    'GCP Service Account':         r'[a-z0-9_-]{6,30}@[a-z0-9_-]{6,30}\.iam\.gserviceaccount\.com',
    'Amazon AWS Access Key ID':    r'(?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}',
    'Amazon AWS Secret Key':       r'''(?i)(?:aws|amazon).{0,40}?["\']([0-9a-zA-Z/+]{40})["\']''',
    'Azure Storage Key':           r'(?i)(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*[A-Za-z0-9+/=]{44,}',
    'Azure Client Secret':         r'(?i)(?:client.?secret|azure.?secret)\s*[:=]\s*["\']?([a-zA-Z0-9~_.]{34,})["\']?',

    # -- Firebase / GCP realtime DB ----------------------------------------
    'Firebase URL':                r'https://[a-zA-Z0-9_-]+\.firebaseio\.com',
    'Firebase Cloud Messaging':    r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}',

    # -- Code hosting / CI -------------------------------------------------
    'GitHub Token (classic)':      r'ghp_[A-Za-z0-9]{36,255}',
    'GitHub Token (fine-grained)': r'github_pat_[A-Za-z0-9_]{22,255}',
    'GitHub Token (other)':        r'gh[ousr]_[A-Za-z0-9]{36,255}',
    'GitHub App Token':            r'(?:ghu|ghs)_[A-Za-z0-9]{36,255}',
    'GitLab Token':                r'glpat-[A-Za-z0-9\-_]{20,}',
    'Bitbucket App Password':      r'(?i)bitbucket.{0,40}?["\']([A-Za-z0-9]{20,})["\']',

    # -- Communication / chat ----------------------------------------------
    'Slack Token':                 r'xox[baprs]-[0-9A-Za-z\-]{10,72}',
    'Slack Webhook':               r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}',
    'Discord Bot Token':           r'(?:N|M|O)[A-Za-z0-9]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}',
    'Discord Webhook':             r'https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,70}',
    'Telegram Bot Token':          r'[0-9]{5,10}:AA[A-Za-z0-9_-]{33}',
    'Microsoft Teams Webhook':     r'https://[a-z0-9-]+\.webhook\.office\.com/webhookb2/[a-f0-9-]+',

    # -- Payment / fintech -------------------------------------------------
    'Stripe Key':                  r'(?:sk|rk|pk)_(?:live|test)_[0-9a-zA-Z]{16,247}',
    'Square Access Token':         r'sq0atp-[0-9A-Za-z\-_]{22,}',
    'Square OAuth Secret':         r'sq0csp-[0-9A-Za-z\-_]{43,}',
    'PayPal Braintree Token':      r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'Shopify Token':               r'shpat_[a-fA-F0-9]{32}',
    'Shopify Shared Secret':       r'shpss_[a-fA-F0-9]{32}',

    # -- Email / messaging SaaS --------------------------------------------
    'Twilio API Key':              r'SK[0-9a-fA-F]{32}',
    'Twilio Account SID':          r'AC[0-9a-fA-F]{32}',
    'SendGrid API Key':            r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
    'Mailgun API Key':             r'key-[0-9a-zA-Z]{32}',
    'Mailchimp API Key':           r'[0-9a-f]{32}-us[0-9]{1,2}',
    'Postmark Token':              r'(?i)(?:postmark|pmak).{0,20}?["\']([a-f0-9-]{36})["\']',

    # -- Monitoring / observability ----------------------------------------
    'Datadog API Key':             r'(?i)(?:datadog|dd).{0,30}?["\']([a-f0-9]{32})["\']',
    'New Relic Key':               r'NRAK-[A-Z0-9]{27}',
    'New Relic Insights Key':      r'NRI(?:I|Q)-[A-Za-z0-9-_]{32}',
    'Sentry DSN':                  r'https://[a-f0-9]{32}@(?:o[0-9]+\.)?(?:sentry\.io|[a-z0-9.-]+)/[0-9]+',
    'PagerDuty Key':               r'(?i)(?:pagerduty|pd).{0,20}?["\']([a-zA-Z0-9+/]{20})["\']',

    # -- CDN / DNS / hosting -----------------------------------------------
    'Cloudflare API Key':          r'(?i)(?:cloudflare|cf).{0,30}?["\']([a-f0-9]{37})["\']',
    'Cloudflare API Token':        r'(?i)(?:cloudflare|cf).{0,30}?["\']([A-Za-z0-9_-]{40})["\']',
    'DigitalOcean Token':          r'dop_v1_[a-f0-9]{64}',
    'Heroku API Key':              r'(?i)heroku.{0,30}?["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']',
    'Vercel Token':                r'(?i)(?:vercel|zeit).{0,20}?["\']([A-Za-z0-9]{24})["\']',
    'Netlify Token':               r'(?i)netlify.{0,20}?["\']([a-zA-Z0-9_-]{40,})["\']',

    # -- Search / maps / analytics -----------------------------------------
    'Algolia API Key':             r'(?i)(?:algolia|alg).{0,30}?["\']([a-f0-9]{32})["\']',
    'Mapbox Token':                r'(?:pk|sk)\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}',

    # -- Package registry tokens -------------------------------------------
    'npm Token':                   r'npm_[A-Za-z0-9]{36}',
    'PyPI Token':                  r'pypi-[A-Za-z0-9_-]{50,}',
    'NuGet API Key':               r'oy2[a-z0-9]{43}',
    'RubyGems Token':              r'rubygems_[a-f0-9]{48}',

    # -- Auth tokens / general ---------------------------------------------
    'JWT':                         r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_.+/=-]{10,}',
    'Bearer Token (header)':       r'''(?i)["']?(?:authorization|bearer)["']?\s*[:=]\s*["']?Bearer\s+([A-Za-z0-9_.~+/=-]{20,})["']?''',
    'Private Key Header':          r'-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE\s+KEY-----',
    'OAuth Client Secret':         r'''(?i)(?:client.?secret|consumer.?secret)\s*[:=]\s*["']([a-zA-Z0-9_-]{16,})["\']''',
    'Basic Auth Embedded':         r'https?://[^"\'\s]+:[^"\'\s]+@[^"\'\s]+',

    # -- Catch-all generic pattern (MEDIUM confidence) ---------------------
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

# ---------------------------------------------------------------------------
# False-positive hints — expanded to cover common JS build noise
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

# ---------------------------------------------------------------------------
# User-Agent rotation pool
# ---------------------------------------------------------------------------
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 '
    '(KHTML, like Gecko) Version/16.5 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 '
    '(KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1',
]

# ---------------------------------------------------------------------------
# Static asset regex (used for endpoint noise filtering)
# ---------------------------------------------------------------------------
_STATIC_ASSET_RE = re.compile(
    r'\.(?:css|js|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|mp[34]|webp|webm|avif|pdf)$',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def is_probably_noise(value: str) -> bool:
    """Quick filter to discard strings that are clearly not secrets."""
    low = value.lower()
    if any(hint in low for hint in _FP_HINT_SET):
        return True
    if len(set(value)) <= 3:
        return True
    if re.fullmatch(r'[0-9a-fA-F]+', value) and len(value) < 32:
        return True
    return False


def is_noise_endpoint(path: str) -> bool:
    """Return True if the URL path is almost certainly a static asset, not an API."""
    if _STATIC_ASSET_RE.search(path):
        return True
    if '/' not in path.lstrip('/') and '.' in path:
        return True
    return False


def mask(value: str) -> str:
    """Mask a secret value for safe display: first 4 + last 4 chars."""
    return value[:4] + "***" + value[-4:] if len(value) > 10 else value
