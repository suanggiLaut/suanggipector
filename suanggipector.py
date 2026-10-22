#!/usr/bin/env python3
"""
suanggipector v2.3 — JavaScript Reconnaissance Scanner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Deep Chunk Discovery | 40+ Secret Patterns | Entropy Analysis
Source Map Reconstruction | AST Sink Extraction | WAF Detection

Usage:
    python suanggipector.py -u https://target.com
    python suanggipector.py -u https://target.com --extract-sourcemaps --ast-analysis --output-json results.json

https://github.com/suanggiLaut/suanggipector
"""

import argparse
import json
import os
import re
import sys
import threading
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from colorama import init, Fore, Style

# -- Local imports ----------------------------------------------------------
from core.rules import (
    REGEX_PATTERNS, HIGH_CONFIDENCE_TYPES,
    is_probably_noise, is_noise_endpoint, mask,
)
from core.entropy import (
    scan_high_entropy_strings, scan_suspicious_b64,
)
from core.crawler import (
    request_with_retry, deep_discover_js_chunks, get_scripts,
)
from modules.sourcemap import discover_source_map, reconstruct_sources
from modules.ast_analyzer import ASTAnalyzer

init(autoreset=True)

# ---------------------------------------------------------------------------
# Global thread-safe result store
# ---------------------------------------------------------------------------
RESULTS_LOCK = threading.Lock()
RESULTS = {
    "target": None,
    "waf_detected": [],
    "js_files": [],
    "js_files_discovered": [],
    "js_files_failed": [],
    "source_maps": [],
    "source_maps_reconstructed": [],
    "endpoints": set(),
    "findings": [],
    "high_entropy": [],
    "suspicious_b64": [],
    "ast_sinks": [],
    "ast_api_routes": [],
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
_BANNER = r"""
███████╗██╗   ██╗ █████╗ ███╗   ██╗ ██████╗  ██████╗ ██╗██████╗ ███████╗ ██████╗████████╗ ██████╗ ██████╗
██╔════╝██║   ██║██╔══██╗████╗  ██║██╔════╝ ██╔════╝ ██║██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
███████╗██║   ██║███████║██╔██╗ ██║██║  ███╗██║  ███╗██║██████╔╝█████╗  ██║        ██║   ██║   ██║██████╔╝
╚════██║██║   ██║██╔══██║██║╚██╗██║██║   ██║██║   ██║╚═╝██╔═══╝ ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
███████║╚██████╔╝██║  ██║██║ ╚████║╚██████╔╝╚██████╔╝██╗██║     ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝

    suanggipector v2.3 — JavaScript Reconnaissance Scanner
    Deep Chunk Discovery | 40+ Secrets | Entropy | Source Map Recon | AST Analysis
"""


def print_banner():
    print(Fore.CYAN + _BANNER)


# ---------------------------------------------------------------------------
# Content scanner (regex + entropy + b64 + sourcemap)
# ---------------------------------------------------------------------------
def scan_content(source, content, entropy_threshold, output_file=None,
                  do_sourcemap=False, js_url=None):
    """Scan a single JS file/inline script for secrets, endpoints, entropy."""
    found_something = False
    output_lines = []

    for key, pattern in REGEX_PATTERNS.items():
        matches = re.findall(pattern, content)
        if not matches:
            continue

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
            display_val = (
                match_str if key == 'URL Paths'
                else f"{mask(match_str)} [{confidence}]"
            )
            result = Fore.WHITE + f"    - {display_val}"
            print(result)
            if output_file:
                output_lines.append(f"    - {display_val}")

            with RESULTS_LOCK:
                RESULTS["findings"].append({
                    "source": source,
                    "type": key,
                    "value": match_str if key == 'URL Paths' else mask(match_str),
                    "confidence": "N/A" if key == 'URL Paths' else confidence,
                })
                if key == 'URL Paths':
                    RESULTS["endpoints"].add(match_str)

    if output_file and output_lines:
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write('\n'.join(output_lines) + '\n')

    entropy_found = scan_high_entropy_strings(
        content, source, entropy_threshold, output_file,
        results=RESULTS, results_lock=RESULTS_LOCK,
    )
    b64_found = scan_suspicious_b64(
        content, source, output_file,
        results=RESULTS, results_lock=RESULTS_LOCK,
    )

    if do_sourcemap and js_url:
        discover_source_map(
            js_url, content, output_file,
            results=RESULTS, results_lock=RESULTS_LOCK,
        )

    return found_something or entropy_found or b64_found


# ---------------------------------------------------------------------------
# Fallback fetch+scan for --no-deep-crawl mode
# ---------------------------------------------------------------------------
def _fetch_and_scan_simple(link, entropy_threshold, output_file, do_sourcemap,
                            delay_min=0.0, delay_max=0.0, retries=3):
    if delay_max > 0:
        time.sleep(random.uniform(delay_min, delay_max))
    try:
        response = request_with_retry(
            link, timeout=10, retries=retries,
            base_delay=1.0, rotate_ua=True,
        )
        response.raise_for_status()
        scan_content(
            link, response.text, entropy_threshold, output_file,
            do_sourcemap=do_sourcemap, js_url=link,
        )
        return link, True, None
    except requests.exceptions.RequestException as e:
        with RESULTS_LOCK:
            RESULTS["js_files_failed"].append({"url": link, "error": str(e)})
        return link, False, str(e)


# ---------------------------------------------------------------------------
# Summary printer
# ---------------------------------------------------------------------------
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
        lines.append(f"JS files (deep)   : +{discovered} chunks discovered")
    lines.append(f"Total JS scanned  : {total_scanned} ({failed} failed)")
    lines.append(f"Source maps found : {len(RESULTS['source_maps'])}")

    reconstructed = RESULTS.get('source_maps_reconstructed', [])
    if reconstructed:
        total_files = sum(len(r.get('files_written', [])) for r in reconstructed)
        lines.append(f"Source maps recon : {len(reconstructed)} maps, {total_files} files written")

    lines.append(f"Unique endpoints  : {len(RESULTS['endpoints'])}")

    if RESULTS.get('ast_sinks'):
        lines.append(f"AST sinks found   : {len(RESULTS['ast_sinks'])}")
    if RESULTS.get('ast_api_routes'):
        lines.append(f"AST API routes    : {len(RESULTS['ast_api_routes'])}")

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

    lines.append(f"\n--- HIGH ENTROPY STRINGS: {len(RESULTS['high_entropy'])} ---")
    lines.append(f"--- BASE64-LIKE STRINGS: {len(RESULTS['suspicious_b64'])} ---")
    lines.append("  (see full JSON/txt output for details)")

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


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------
def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description=(
            "suanggipector v2.3 — JS Reconnaissance Scanner with Deep Chunk "
            "Discovery, Entropy Analysis, Source Map Reconstruction, "
            "AST Sink Extraction & WAF Detection"
        ),
        epilog=(
            "Example: python suanggipector.py -u https://target.com "
            "-o results.txt --output-json results.json --ast-analysis"
        ),
    )

    # -- Core arguments (backward-compatible) ------------------------------
    parser.add_argument("-u", "--url", required=True,
                         help="Target URL to scan.")
    parser.add_argument("-o", "--output",
                         help="Save output to .txt file.")
    parser.add_argument("--json",
                         help="Save structured results to JSON file (legacy alias).")
    parser.add_argument("-e", "--entropy", type=float, default=5.0,
                         help="Shannon Entropy threshold (default: 5.0).")
    parser.add_argument("--no-entropy", action="store_true",
                         help="Disable entropy scanning.")
    parser.add_argument("--no-sourcemap", action="store_true",
                         help="Disable source map (.js.map) discovery.")
    parser.add_argument("--no-deep-crawl", action="store_true",
                         help="Disable deep JS chunk discovery.")
    parser.add_argument("--crawl-depth", type=int, default=3,
                         help="Maximum deep crawl depth (default: 3).")
    parser.add_argument("--max-js-files", type=int, default=200,
                         help="Maximum number of JS files to scan (default: 200).")
    parser.add_argument("-c", "--concurrency", type=int, default=8,
                         help="Parallel worker threads (default: 8).")
    parser.add_argument("--delay-min", type=float, default=0.0,
                         help="Min delay (sec) before each request (default: 0).")
    parser.add_argument("--delay-max", type=float, default=0.0,
                         help="Max delay (sec) before each request (default: 0).")
    parser.add_argument("--retries", type=int, default=3,
                         help="Retries with exponential backoff (default: 3).")

    # -- v2.3 NEW flags ----------------------------------------------------
    parser.add_argument("--extract-sourcemaps", action="store_true",
                         help="Download & reconstruct source files from .js.map "
                              "(with path-traversal protection).")
    parser.add_argument("--sourcemap-output", default="sourcemaps_out",
                         help="Output directory for reconstructed sources "
                              "(default: sourcemaps_out).")
    parser.add_argument("--ast-analysis", action="store_true",
                         help="Enable Tree-sitter AST analysis for sink "
                              "extraction (fetch, axios, XHR, API routes).")
    parser.add_argument("--output-json",
                         help="Save structured results to JSON file (v2.3 flag).")

    args = parser.parse_args()

    # Resolve JSON output path (--output-json takes precedence over --json)
    json_output = args.output_json or args.json

    entropy_threshold = args.entropy
    do_sourcemap = not args.no_sourcemap

    requests.packages.urllib3.disable_warnings()
    print(
        Fore.YELLOW +
        "[WARNING] SSL verification disabled (verify=False). "
        "InsecureRequestWarning suppressed."
    )

    target_url = args.url
    output_file = args.output
    RESULTS["target"] = target_url

    if output_file:
        print(Fore.YELLOW + f"[INFO] Results will be saved to: {output_file}")
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=== suanggipector Recon Results (v2.3) ===\n")
            f.write(f"Target: {target_url}\n")
            f.write(f"Entropy Threshold: {entropy_threshold}\n")
            f.write(
                f"Deep Crawl: "
                f"{'OFF' if args.no_deep_crawl else f'ON (depth={args.crawl_depth}, max={args.max_js_files})'}\n"
            )
            f.write(f"AST Analysis: {'ON' if args.ast_analysis else 'OFF'}\n")
            f.write(f"Source Map Extraction: {'ON' if args.extract_sourcemaps else 'OFF'}\n")
            f.write(f"Scan Time: {__import__('datetime').datetime.now()}\n")
            f.write("=" * 50 + "\n")

    # -- Initialize AST analyzer if requested ------------------------------
    ast_analyzer = None
    if args.ast_analysis:
        ast_analyzer = ASTAnalyzer()
        if ast_analyzer.available:
            print(Fore.GREEN + "[AST] Tree-sitter JavaScript parser initialized.")
        else:
            print(
                Fore.YELLOW +
                "[AST] Tree-sitter not available. "
                "Falling back to regex-based route extraction."
            )

    # -- Crawl target -------------------------------------------------------
    js_links, inline_scripts, waf_info = get_scripts(
        target_url, output_file, results=RESULTS
    )

    if not js_links and not inline_scripts:
        print(Fore.YELLOW + "[INFO] No JavaScript files or inline scripts found.")
        if waf_info:
            print(
                Fore.RED +
                f"[INFO] WAF {', '.join(waf_info)} may be blocking content."
            )
        _finalize_json(json_output)
        return

    # -- Scan JS files -------------------------------------------------------
    if js_links:
        initial_count = len(js_links)
        print(Fore.YELLOW + f"\n[INFO] Found {initial_count} JS files from main page.")

        if not args.no_entropy:
            print(Fore.MAGENTA + f"[ENTROPY] Shannon Entropy threshold: {entropy_threshold}")
        if do_sourcemap:
            print(Fore.MAGENTA + "[SOURCEMAP] Auto-discovery active.")
        if args.ast_analysis:
            print(Fore.MAGENTA + "[AST] Sink extraction active.")
        if args.extract_sourcemaps:
            print(Fore.MAGENTA + f"[SOURCEMAP RECON] Output dir: {args.sourcemap_output}")

        if not args.no_deep_crawl:
            # -- Deep crawl mode -----------------------------------------------
            print(
                Fore.YELLOW +
                f"[DEEP CRAWL] Mode active — depth={args.crawl_depth}, "
                f"max_files={args.max_js_files}"
            )
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
                print(Fore.GREEN + f"\n[DEEP CRAWL] +{len(discovered_extra)} extra chunks!")
                if output_file:
                    with open(output_file, 'a', encoding='utf-8') as f:
                        f.write(
                            f"\n[DEEP CRAWL] {len(discovered_extra)} extra JS chunks:\n"
                        )
                        for u in discovered_extra[:50]:
                            f.write(f"  - {u}\n")
                        if len(discovered_extra) > 50:
                            f.write(f"  ... and {len(discovered_extra) - 50} more\n")

            # Scan all fetched content
            print(Fore.YELLOW + f"\n[INFO] Scanning {len(fetched_map)} JS files total...")
            scan_count = 0
            for js_url, js_content in fetched_map.items():
                scan_count += 1
                print(Fore.CYAN + f"[{scan_count}/{len(fetched_map)}] Scanning: {js_url}")
                scan_content(
                    js_url, js_content, entropy_threshold, output_file,
                    do_sourcemap=do_sourcemap, js_url=js_url,
                )

                # AST analysis
                if ast_analyzer:
                    ast_result = ast_analyzer.analyze(js_url, js_content)
                    if ast_result.total > 0:
                        _print_ast_result(ast_result, output_file)

                # Source map reconstruction
                if args.extract_sourcemaps:
                    reconstruct_sources(
                        js_url, js_content, args.sourcemap_output,
                        results=RESULTS, results_lock=RESULTS_LOCK,
                    )

        else:
            # -- No deep crawl mode -------------------------------------------
            print(
                Fore.YELLOW +
                f"[INFO] Deep crawl disabled. Scanning {initial_count} JS files..."
            )
            RESULTS["js_files"] = js_links

            with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
                futures = {
                    executor.submit(
                        _fetch_and_scan_simple, link, entropy_threshold,
                        output_file, do_sourcemap,
                        args.delay_min, args.delay_max, args.retries,
                    ): link
                    for link in js_links
                }
                done_count = 0
                for future in as_completed(futures):
                    link = futures[future]
                    done_count += 1
                    try:
                        _, success, error = future.result()
                        status = (
                            Fore.GREEN + "OK" if success
                            else Fore.RED + f"FAILED ({error})"
                        )
                        print(
                            Fore.CYAN +
                            f"[{done_count}/{len(js_links)}] {link} -> {status}"
                        )
                    except Exception as e:
                        print(
                            Fore.RED +
                            f"[{done_count}/{len(js_links)}] {link} -> Exception: {e}"
                        )

    # -- Inline scripts -------------------------------------------------------
    if inline_scripts:
        print(
            Fore.YELLOW +
            f"\n[INFO] Found {len(inline_scripts)} inline scripts. Starting scan..."
        )
        for i, script_content in enumerate(inline_scripts):
            source_name = f"Inline Script #{i+1} from {target_url}"
            print(Fore.CYAN + f"\n[Inline {i+1}/{len(inline_scripts)}] Scanning: {source_name}")
            scan_content(
                source_name, script_content, entropy_threshold,
                output_file, do_sourcemap=False,
            )
            if ast_analyzer:
                ast_result = ast_analyzer.analyze(source_name, script_content)
                if ast_result.total > 0:
                    _print_ast_result(ast_result, output_file)

    # -- Finalize --------------------------------------------------------------
    print_summary(waf_info, output_file)
    _finalize_json(json_output)


# ---------------------------------------------------------------------------
# AST result printer
# ---------------------------------------------------------------------------
def _print_ast_result(ast_result, output_file=None):
    """Print AST analysis findings and store in global RESULTS."""
    output_lines = []

    if ast_result.sinks:
        header = Fore.MAGENTA + f"\n[AST SINKS] in: {ast_result.source_url}"
        print(header)
        output_lines.append(f"\n[AST SINKS] in: {ast_result.source_url}")
        for s in ast_result.sinks:
            line = f"  |__ [{s.kind}] {s.value}  (line {s.line})"
            print(Fore.WHITE + line)
            output_lines.append(line)
            with RESULTS_LOCK:
                RESULTS["ast_sinks"].append(s.to_dict() if hasattr(s, 'to_dict') else {
                    "source": ast_result.source_url,
                    "kind": s.kind,
                    "value": s.value,
                    "line": s.line,
                })

    if ast_result.api_routes:
        header = Fore.BLUE + f"\n[AST ROUTES] in: {ast_result.source_url}"
        print(header)
        output_lines.append(f"\n[AST ROUTES] in: {ast_result.source_url}")
        for r in ast_result.api_routes:
            line = f"  |__ {r.value}  (line {r.line})"
            print(Fore.WHITE + line)
            output_lines.append(line)
            with RESULTS_LOCK:
                RESULTS["ast_api_routes"].append({
                    "source": ast_result.source_url,
                    "route": r.value,
                    "line": r.line,
                })

    if output_file and output_lines:
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write('\n'.join(output_lines) + '\n')


if __name__ == "__main__":
    main()
