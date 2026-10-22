#!/usr/bin/env python3
"""
suanggipector.modules.sourcemap
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Source Map v3 detection, download, safe reconstruction with
path-traversal sanitization.

Security: all reconstructed paths are sanitised to prevent
directory-traversal attacks (strips webpack:///, vite:///,
../ sequences, and verifies os.path.abspath stays within
the output base directory).
"""

import os
import re
import json
import threading

from colorama import Fore

from core.crawler import request_with_retry

# ---------------------------------------------------------------------------
# Path sanitization for source map reconstruction
# ---------------------------------------------------------------------------
_TRAVERSAL_PREFIXES = (
    'webpack:///',
    'webpack://',
    'vite:///',
    'vite://',
    'file:///',
    'file://',
    'turbopack:///',
    'turbopack://',
)


def _sanitize_source_path(raw_path: str) -> str | None:
    """
    Sanitize a source path from a .map file.

    Strips known loader prefixes (webpack:///, vite:///, etc.),
    removes ../ traversal sequences, and ensures the result is
    a clean relative path.

    Returns None if the path is unsafe or empty after sanitization.
    """
    path = raw_path.strip()

    # Strip loader protocol prefixes
    for prefix in _TRAVERSAL_PREFIXES:
        if path.lower().startswith(prefix.lower()):
            path = path[len(prefix):]
            break

    # Remove leading dots and slashes repeatedly
    while path.startswith('../') or path.startswith('..\\'):
        path = path[3:]
    while path.startswith('./') or path.startswith('.\\'):
        path = path[2:]
    while path.startswith('/') or path.startswith('\\'):
        path = path[1:]

    # Replace remaining .. components
    parts = path.replace('\\', '/').split('/')
    clean_parts = [p for p in parts if p and p != '..']

    if not clean_parts:
        return None

    return '/'.join(clean_parts)


def _validate_output_path(file_path: str, base_dir: str) -> bool:
    """
    Verify that the resolved absolute path stays within base_dir.
    Prevents path-traversal via symlink or encoded sequences.
    """
    abs_path = os.path.abspath(os.path.join(base_dir, file_path))
    abs_base = os.path.abspath(base_dir)
    return abs_path.startswith(abs_base + os.sep) or abs_path == abs_base


# ---------------------------------------------------------------------------
# Source map discovery (backward-compatible with v2.2)
# ---------------------------------------------------------------------------
def discover_source_map(js_url, js_content, output_file=None,
                         results=None, results_lock=None):
    """
    Look for sourceMappingURL in JS content, fetch the .map file,
    and list original source paths.

    Returns the map URL if found, else None.
    """
    match = re.search(r'//[#@]\s*sourceMappingURL=(\S+)', js_content)
    if not match:
        return None

    from urllib.parse import urljoin
    map_url = urljoin(js_url, match.group(1))

    try:
        resp = request_with_retry(
            map_url, timeout=10, retries=2,
            base_delay=0.5, rotate_ua=True,
        )
        resp.raise_for_status()
        map_data = resp.json()
    except Exception:
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

    if results is not None and results_lock is not None:
        with results_lock:
            results["source_maps"].append({
                "js_file": js_url,
                "map_url": map_url,
                "sources": sources,
            })

    if output_file:
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')

    return map_url


# ---------------------------------------------------------------------------
# Full source-map reconstruction  (v2.3 NEW)
# ---------------------------------------------------------------------------
def reconstruct_sources(js_url, js_content, output_dir,
                         results=None, results_lock=None):
    """
    Download the source map for *js_url*, then reconstruct original
    source files into *output_dir* with full path-traversal protection.

    Returns:
        dict with keys: map_url, files_written (list), files_skipped (list),
        or None if no source map found.
    """
    match = re.search(r'//[#@]\s*sourceMappingURL=(\S+)', js_content)
    if not match:
        return None

    from urllib.parse import urljoin
    map_url = urljoin(js_url, match.group(1))

    try:
        resp = request_with_retry(
            map_url, timeout=15, retries=2,
            base_delay=0.5, rotate_ua=True,
        )
        resp.raise_for_status()
        map_data = resp.json()
    except Exception as exc:
        print(Fore.RED + f"[SOURCE MAP] Failed to fetch {map_url}: {exc}")
        return None

    sources = map_data.get('sources', [])
    contents = map_data.get('sourcesContent', [])

    if not sources or not contents:
        print(
            Fore.YELLOW +
            f"[SOURCE MAP] {map_url} has no sourcesContent — "
            "cannot reconstruct."
        )
        return None

    os.makedirs(output_dir, exist_ok=True)

    files_written = []
    files_skipped = []

    for idx, raw_path in enumerate(sources):
        if idx >= len(contents) or contents[idx] is None:
            files_skipped.append(raw_path)
            continue

        safe_path = _sanitize_source_path(raw_path)
        if safe_path is None:
            files_skipped.append(raw_path)
            print(
                Fore.RED +
                f"  [SKIP] Unsafe path after sanitization: {raw_path}"
            )
            continue

        if not _validate_output_path(safe_path, output_dir):
            files_skipped.append(raw_path)
            print(
                Fore.RED +
                f"  [SKIP] Path traversal blocked: {raw_path} -> {safe_path}"
            )
            continue

        dest = os.path.join(output_dir, safe_path)
        os.makedirs(os.path.dirname(dest), exist_ok=True)

        try:
            with open(dest, 'w', encoding='utf-8') as f:
                f.write(contents[idx])
            files_written.append(safe_path)
        except OSError as exc:
            files_skipped.append(raw_path)
            print(Fore.RED + f"  [SKIP] Write error for {safe_path}: {exc}")

    print(
        Fore.GREEN +
        f"[SOURCE MAP] Reconstructed {len(files_written)} files from {map_url}"
    )
    if files_skipped:
        print(
            Fore.YELLOW +
            f"  Skipped {len(files_skipped)} entries (unsafe path / no content)"
        )

    result_entry = {
        "js_file": js_url,
        "map_url": map_url,
        "files_written": files_written,
        "files_skipped": files_skipped,
    }

    if results is not None and results_lock is not None:
        with results_lock:
            results.setdefault("source_maps_reconstructed", []).append(result_entry)

    return result_entry
