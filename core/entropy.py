#!/usr/bin/env python3
"""
suanggipector.core.entropy
~~~~~~~~~~~~~~~~~~~~~~~~~~
Shannon entropy calculator, high-entropy string scanner,
and suspicious Base64-like string detector.
"""

import re
import math
import threading
from collections import Counter

from colorama import Fore

from .rules import is_probably_noise, mask

# ---------------------------------------------------------------------------
# Patterns for entropy / base64 detection
# ---------------------------------------------------------------------------
SUSPICIOUS_STRING_PATTERN = r'["\']([A-Za-z0-9+/=]{20,})["\']'
HIGH_ENTROPY_PATTERN      = r'["\']([a-zA-Z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]{16,})["\']'


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy for a given string."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def scan_high_entropy_strings(content, source, entropy_threshold,
                               output_file=None, results=None, results_lock=None):
    """
    Scan content for high-entropy strings above the given threshold.
    Thread-safe when *results* dict and *results_lock* are provided.
    """
    output_lines = []
    found_something = False

    matches = re.findall(HIGH_ENTROPY_PATTERN, content)
    high_entropy_matches = []
    for m in matches:
        if is_probably_noise(m):
            continue
        entropy = calculate_shannon_entropy(m)
        if entropy > entropy_threshold:
            high_entropy_matches.append((m, entropy))

    if high_entropy_matches:
        seen = set()
        unique_matches = []
        for m, entropy in high_entropy_matches:
            if m not in seen:
                seen.add(m)
                unique_matches.append((m, entropy))

        if unique_matches:
            header = Fore.MAGENTA + (
                f"\n[HIGH ENTROPY] High Entropy Strings in: {source} "
                f"(Threshold: {entropy_threshold})"
            )
            print(header)
            if output_file:
                output_lines.append(
                    f"\n[HIGH ENTROPY] Strings in: {source} "
                    f"(Threshold: {entropy_threshold})"
                )

            for match_str, entropy_val in sorted(
                unique_matches, key=lambda x: x[1], reverse=True
            ):
                masked = mask(match_str)
                result = Fore.WHITE + f"  |__ Entropy: {entropy_val:.2f} | String: {masked}"
                print(result)
                if output_file:
                    output_lines.append(
                        f"  |__ Entropy: {entropy_val:.2f} | String: {masked}"
                    )
                if results is not None and results_lock is not None:
                    with results_lock:
                        results["high_entropy"].append({
                            "source": source,
                            "entropy": round(entropy_val, 2),
                            "value_masked": masked,
                        })

            found_something = True

    if output_file and output_lines:
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write('\n'.join(output_lines) + '\n')

    return found_something


def scan_suspicious_b64(content, source, output_file=None,
                         results=None, results_lock=None):
    """
    Scan content for suspicious Base64-like strings.
    Thread-safe when *results* dict and *results_lock* are provided.
    """
    output_lines = []
    found_something = False

    matches = re.findall(SUSPICIOUS_STRING_PATTERN, content)
    seen = set()
    unique_matches = [m for m in matches if not (m in seen or seen.add(m))]
    candidates = [
        m for m in unique_matches
        if len(set(m)) > 4 and not is_probably_noise(m)
    ]

    if candidates:
        header = Fore.BLUE + f"\n[BASE64] Suspicious Base64-like Strings in: {source}"
        print(header)
        if output_file:
            output_lines.append(
                f"\n[BASE64] Suspicious Base64-like Strings in: {source}"
            )

        for match_str in candidates:
            masked = mask(match_str)
            result = Fore.WHITE + f"  |__ {masked}"
            print(result)
            if output_file:
                output_lines.append(f"  |__ {masked}")
            if results is not None and results_lock is not None:
                with results_lock:
                    results["suspicious_b64"].append({
                        "source": source,
                        "value_masked": masked,
                    })

        found_something = True

    if output_file and output_lines:
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write('\n'.join(output_lines) + '\n')

    return found_something
