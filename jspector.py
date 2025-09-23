# suanggiLaut
import requests
import argparse
import re
import os
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import init, Fore, Style
import sys

init(autoreset=True)

REGEX_PATTERNS = {
    'Google API Key': r'AIza[0-9A-Za-z-_]{35}',
    'Google OAuth Token': r'ya29\.[0-9A-Za-z\-_]+',
    'Amazon AWS Access Key ID': r'AKIA[0-9A-Z]{16}',
    'Amazon AWS Secret Key': r'[0-9a-zA-Z/+]{40}',
    'Facebook Access Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
    'Twitter Bearer Token': r'[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}',
    'GitHub Token': r'ghp_[a-zA-Z0-9]{36}',
    'Slack Token': r'xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}',
    'Stripe API Key': r'sk_live_[0-9a-zA-Z]{24}',
    'Stripe Restricted Key': r'rk_live_[0-9a-zA-Z]{24}',
    'PayPal Braintree Access Token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'Twilio API Key': r'SK[0-9a-fA-F]{32}',
    'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
    'Heroku API Key': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    
    'URL Paths': r'["\'](/[^/"\']+?/)["\']',
    'API Endpoints': r'["\'](?:https?:)?//[^/"\']+?(?:/api/v[0-9]/[^/"\']+?)["\']',
    'Firebase URL': r'https://[a-zA-Z0-9_-]+\.firebaseio\.com',
    'Database URLs': r'(?:mysql|postgres|mongodb)://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9._-]+:[0-9]+/[a-zA-Z0-9_]+',
    
    'Email Addresses': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'IP Addresses': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    'Credit Card Numbers': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b',
    'SSH Private Keys': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
    'JWT Tokens': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
    
    'Generic Secrets': r'(?i)["\'](api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|pwd|passwd)["\']\s*:\s*["\']([a-zA-Z0-9!@#$%^&*()_+-=]{8,})["\']',
    'Config Variables': r'(?i)(?:const|var|let)\s+(apiKey|secret|token|password)\s*=\s*["\']([^"'\']+)["\']',
}

KEYWORDS = [
    'api_key', 'apiKey', 'secret', 'token', 'auth', 'password', 'credential',
    'access_key', 'private_key', 'database', 'endpoint', 'config', 'configuration',
    'admin', 'login', 'signin', 'oauth', 'jwt', 'bearer', 'firebase', 'aws',
    'stripe', 'paypal', 'twilio', 'sendgrid', 'mailgun', 'heroku'
]

class SuanggiScanner:
    def __init__(self, max_threads=10):
        self.max_threads = max_threads
        self.visited_urls = set()
        self.results = []
        self.lock = threading.Lock()
        
    def print_banner(self):
        """Menampilkan banner ASCII art untuk tools."""
        banner = """
███████╗██╗   ██╗ █████╗ ███╗   ██╗ ██████╗  ██████╗ ██╗
██╔════╝██║   ██║██╔══██╗████╗  ██║██╔════╝ ██╔════╝ ██║
███████╗██║   ██║███████║██╔██╗ ██║██║  ███╗██║  ███╗██║
╚════██║██║   ██║██╔══██║██║╚██╗██║██║   ██║██║   ██║╚═╝
███████║╚██████╔╝██║  ██║██║ ╚████║╚██████╔╝╚██████╔╝██╗
╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝

Advanced JavaScript Inspector for Reconnaissance
        """
        print(Fore.CYAN + banner)
        print(Fore.YELLOW + "Suanggi v2.0 - Deep JS Analysis Tool")
        print(Fore.YELLOW + "=" * 50 + "\n")

    def get_wayback_urls(self, domain):
        """Mendapatkan URL dari Wayback Machine (implementasi dasar)."""
        wayback_urls = []
        try:
            wayback_api = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&collapse=urlkey"
            response = requests.get(wayback_api, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for entry in data[1:]:  
                    if len(entry) > 2:
                        wayback_urls.append(entry[2])
            print(Fore.GREEN + f"[Wayback] Found {len(wayback_urls)} historical URLs")
        except Exception as e:
            print(Fore.RED + f"[Wayback] Error: {e}")
        return wayback_urls[:50]  

    def extract_urls_from_js(self, content, base_url):
        """Mengekstrak URL dari konten JavaScript."""
        urls = set()
        patterns = [
            r'["\'](https?://[^"\']+)["\']',
            r'["\'](/[^"\']+)["\']',
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'\.href\s*=\s*["\']([^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.get\(["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if match.startswith('http'):
                    urls.add(match)
                else:
                    urls.add(urljoin(base_url, match))
        return list(urls)

    def crawl_page(self, url, depth=0, max_depth=2):
        """Crawling halaman dengan depth tertentu."""
        if depth > max_depth or url in self.visited_urls:
            return [], []
        
        self.visited_urls.add(url)
        js_files = set()
        inline_scripts = []
        page_urls = set()
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=15, verify=False)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for script_tag in soup.find_all('script', src=True):
                full_url = urljoin(url, script_tag.get('src'))
                js_files.add(full_url)
            
            for script_tag in soup.find_all('script', src=False):
                if script_tag.string:
                    inline_scripts.append({
                        'url': url,
                        'content': script_tag.string,
                        'depth': depth
                    })
            
            if depth < max_depth:
                for link in soup.find_all('a', href=True):
                    href = link.get('href')
                    if href and not href.startswith(('javascript:', 'mailto:', 'tel:')):
                        full_url = urljoin(url, href)
                        if full_url not in self.visited_urls:
                            page_urls.add(full_url)
            
            print(Fore.GREEN + f"[Crawl] Depth {depth}: Found {len(js_files)} JS files, {len(inline_scripts)} inline scripts, {len(page_urls)} links")
            
        except Exception as e:
            print(Fore.RED + f"[Crawl] Error crawling {url}: {e}")
        
        return list(js_files), inline_scripts, list(page_urls)

    def deep_crawl(self, start_url, max_depth=2):
        """Crawling mendalam dengan multi-threading."""
        all_js_files = set()
        all_inline_scripts = []
        urls_to_crawl = [(start_url, 0)]
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_url = {}
            
            while urls_to_crawl or future_to_url:
                while urls_to_crawl:
                    url, depth = urls_to_crawl.pop(0)
                    if url not in self.visited_urls and depth <= max_depth:
                        future = executor.submit(self.crawl_page, url, depth, max_depth)
                        future_to_url[future] = (url, depth)
                
                done, _ = as_completed(future_to_url), 5  
                for future in done:
                    if future in future_to_url:
                        url, depth = future_to_url.pop(future)
                        try:
                            js_files, inline_scripts, new_urls = future.result()
                            all_js_files.update(js_files)
                            all_inline_scripts.extend(inline_scripts)
                            
                            for new_url in new_urls:
                                if new_url not in self.visited_urls:
                                    urls_to_crawl.append((new_url, depth + 1))
                        
                        except Exception as e:
                            print(Fore.RED + f"[Crawl] Error processing {url}: {e}")
        
        return list(all_js_files), all_inline_scripts

    def scan_content(self, source, content, content_type="js"):
        """Memindai konten menggunakan pola regex dan kata kunci."""
        findings = []
        
        for pattern_name, pattern in REGEX_PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                for match in matches:
                    match_str = match if isinstance(match, str) else match[1] if len(match) > 1 else match[0]
                    if match_str and len(match_str) > 3:  # Filter hasil yang terlalu pendek
                        findings.append({
                            'type': 'regex',
                            'pattern': pattern_name,
                            'value': match_str.strip(),
                            'source': source,
                            'content_type': content_type
                        })
        
        for keyword in KEYWORDS:
            if re.search(rf'\b{re.escape(keyword)}\b', content, re.IGNORECASE):
                context_match = re.search(
                    rf'.{{0,50}}\b{re.escape(keyword)}\b.{{0,50}}', 
                    content, 
                    re.IGNORECASE
                )
                context = context_match.group(0) if context_match else "Keyword found"
                
                findings.append({
                    'type': 'keyword',
                    'pattern': 'Sensitive Keyword',
                    'value': keyword,
                    'context': context,
                    'source': source,
                    'content_type': content_type
                })
        
        return findings

    def scan_url(self, url):
        """Memindai satu URL (JS file)."""
        try:
            response = requests.get(url, timeout=10, verify=False)
            response.raise_for_status()
            
            findings = self.scan_content(url, response.text, "js")

            additional_urls = self.extract_urls_from_js(response.text, url)
            
            return findings, additional_urls
            
        except Exception as e:
            print(Fore.RED + f"[Scan] Error scanning {url}: {e}")
            return [], []

    def display_findings(self, findings):
        """Menampilkan hasil temuan dengan format yang rapi."""
        if not findings:
            print(Fore.YELLOW + "[INFO] Tidak ada temuan yang signifikan.")
            return
        
        grouped_findings = {}
        for finding in findings:
            source = finding['source']
            if source not in grouped_findings:
                grouped_findings[source] = []
            grouped_findings[source].append(finding)
        
        for source, source_findings in grouped_findings.items():
            print(Fore.GREEN + f"\n[+] Temuan di: {source}")
            
            for finding in source_findings:
                color = Fore.RED if finding['type'] == 'regex' else Fore.YELLOW
                print(color + f"  └── {finding['pattern']}: {finding['value']}")
                
                if 'context' in finding:
                    print(Fore.CYAN + f"      Konteks: {finding['context']}")

    def save_results(self, findings, output_file, format='text'):
        """Menyimpan hasil dalam format yang berbeda."""
        if format == 'json':
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(findings, f, indent=2, ensure_ascii=False)
            print(Fore.GREEN + f"[INFO] Results saved as JSON to: {output_file}")
        
        elif format == 'text':
            with open(output_file, 'w', encoding='utf-8') as f:
                for finding in findings:
                    f.write(f"Source: {finding['source']}\n")
                    f.write(f"Type: {finding['type']}\n")
                    f.write(f"Pattern: {finding['pattern']}\n")
                    f.write(f"Value: {finding['value']}\n")
                    if 'context' in finding:
                        f.write(f"Context: {finding['context']}\n")
                    f.write("-" * 50 + "\n")
            print(Fore.GREEN + f"[INFO] Results saved as text to: {output_file}")

def main():
    scanner = SuanggiScanner(max_threads=15)
    scanner.print_banner()
    
    parser = argparse.ArgumentParser(description="Suanggi - Advanced JS Analysis Tool")
    parser.add_argument("-u", "--url", required=True, help="URL target untuk di-scan")
    parser.add_argument("-d", "--depth", type=int, default=1, help="Kedalaman crawling (default: 1)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Jumlah thread (default: 10)")
    parser.add_argument("-o", "--output", help="File untuk menyimpan output")
    parser.add_argument("-f", "--format", choices=['text', 'json'], default='text', help="Format output")
    parser.add_argument("--wayback", action="store_true", help="Gunakan Wayback Machine")
    parser.add_argument("--no-crawl", action="store_true", help="Nonaktifkan crawling")
    args = parser.parse_args()

    requests.packages.urllib3.disable_warnings()
    
    scanner.max_threads = args.threads
    
    all_findings = []
    
    try:
        if args.wayback:
            print(Fore.CYAN + "[Wayback] Mengambil URL dari Wayback Machine...")
            domain = urlparse(args.url).netloc
            wayback_urls = scanner.get_wayback_urls(domain)
            
            for wayback_url in wayback_urls[:8]:  
                print(Fore.YELLOW + f"[Wayback] Scanning: {wayback_url}")
                js_links, inline_scripts = scanner.get_scripts(wayback_url)
    
        if not args.no_crawl:
            print(Fore.CYAN + f"[Crawl] Memulai deep crawling dengan depth {args.depth}...")
            js_links, inline_scripts = scanner.deep_crawl(args.url, max_depth=args.depth)
        else:
            print(Fore.CYAN + "[Crawl] Crawling dinonaktifkan, menggunakan URL langsung...")
            js_links, inline_scripts = scanner.crawl_page(args.url, 0, 0)[:2]

        print(Fore.CYAN + f"[Scan] Memulai scanning dengan {scanner.max_threads} threads...")
        
        with ThreadPoolExecutor(max_workers=scanner.max_threads) as executor:
            future_to_url = {executor.submit(scanner.scan_url, url): url for url in js_links}
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    findings, additional_urls = future.result()
                    all_findings.extend(findings)
                    print(Fore.GREEN + f"[Scan] Completed: {url} ({len(findings)} findings)")
                except Exception as e:
                    print(Fore.RED + f"[Scan] Error: {url} - {e}")

        print(Fore.CYAN + "[Scan] Memindai inline scripts...")
        for script in inline_scripts:
            findings = scanner.scan_content(script['url'], script['content'], "inline")
            all_findings.extend(findings)

        scanner.display_findings(all_findings)
        
        if args.output:
            scanner.save_results(all_findings, args.output, args.format)
        
        print(Fore.GREEN + f"\n[INFO] Pemindaian selesai. Total temuan: {len(all_findings)}")
        
    except KeyboardInterrupt:
        print(Fore.RED + "\n[INFO] Pemindaian dihentikan oleh pengguna.")
    except Exception as e:
        print(Fore.RED + f"[ERROR] Error utama: {e}")

if __name__ == "__main__":
    main()
