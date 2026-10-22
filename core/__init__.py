# suanggipector/core — Core scanning engine
from .rules import (
    REGEX_PATTERNS,
    HIGH_CONFIDENCE_TYPES,
    FALSE_POSITIVE_HINTS,
    USER_AGENTS,
    is_probably_noise,
    is_noise_endpoint,
    mask,
)
from .entropy import (
    calculate_shannon_entropy,
    scan_high_entropy_strings,
    scan_suspicious_b64,
)
from .crawler import (
    request_with_retry,
    extract_js_refs_from_content,
    deep_discover_js_chunks,
    get_scripts,
    detect_waf,
)
