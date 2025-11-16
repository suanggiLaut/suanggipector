# suanggi_laut
import requests
import argparse
import re
import os
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import init, Fore, Style

init(autoreset=True)

REGEX_PATTERNS = {
    'URL Paths': r'["\'](/[^/][a-zA-Z0-9_./-]+)["\']',
    'Google API Key': r'AIza[0-9A-Za-z-_]{35}',
    'Amazon AWS Access Key ID': r'AKIA[0-9A-Z]{16}',
    'Firebase URL': r'https://[a-zA-Z0-9_-]+\.firebaseio\.com',
    'Generic API Key/Secret': r'(?i)["\'](api_key|secret|token|auth|password)["\']\s*:\s*["\']([a-zA-Z0-9_.-]+)["\']'
}

def print_banner():
    """Menampilkan banner ASCII art untuk tools."""
    banner = """
███████╗██╗   ██╗ █████╗ ███╗   ██╗ ██████╗  ██████╗ ██╗
██╔════╝██║   ██║██╔══██╗████╗  ██║██╔════╝ ██╔════╝ ██║
███████╗██║   ██║███████║██╔██╗ ██║██║  ███╗██║  ███╗██║
╚════██║██║   ██║██╔══██║██║╚██╗██║██║   ██║██║   ██║╚═╝
███████║╚██████╔╝██║  ██║██║ ╚████║╚██████╔╝╚██████╔╝██╗
╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝

A JavaScript Inspector for Reconnaissance
"""
    print(Fore.CYAN + banner)

def get_scripts(url):
    """Mengambil URL file JS eksternal dan konten script inline dari target."""
    print(Fore.YELLOW + f"[INFO] Merayapi target: {url}")
    js_files = set()
    inline_scripts = []
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=15, verify=False, allow_redirects=True)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        for script_tag in soup.find_all('script', src=True):
            full_url = urljoin(url, script_tag.get('src'))
            js_files.add(full_url)
        
        for script_tag in soup.find_all('script', src=False):
            if script_tag.string:
                inline_scripts.append(script_tag.string)

    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[ERROR] Gagal mengakses {url}: {e}")
    
    return list(js_files), inline_scripts

def scan_content(source, content, output_file=None):
    """Memindai konten menggunakan pola regex dan menampilkan hasilnya."""
    found_something = False
    output_lines = []
    
    for key, pattern in REGEX_PATTERNS.items():
        matches = re.findall(pattern, content)
        if matches:
            if not found_something:
                header = Fore.GREEN + f"\n[+] Temuan di: {source}"
                print(header)
                if output_file: output_lines.append(f"\n[+] Temuan di: {source}")
                found_something = True
            
            result_header = Fore.CYAN + f"  └── Potensi '{key}':"
            print(result_header)
            if output_file: output_lines.append(f"  └── Potensi '{key}':")

            for match in matches:
                match_str = match if isinstance(match, str) else match[1] if len(match) > 1 else match[0]
                result = Fore.WHITE + f"    - {match_str.strip()}"
                print(result)
                if output_file: output_lines.append(f"    - {match_str.strip()}")
            
    if output_file and output_lines:
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write('\n'.join(output_lines) + '\n')

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Suanggi - JS File Endpoint & Secret Finder")
    parser.add_argument("-u", "--url", required=True, help="URL target untuk di-scan.")
    parser.add_argument("-o", "--output", help="File untuk menyimpan output.")
    args = parser.parse_args()

    requests.packages.urllib3.disable_warnings()
    target_url = args.url
    output_file = args.output
    
    if output_file:
        print(Fore.YELLOW + f"[INFO] Hasil akan disimpan ke: {output_file}")
        open(output_file, 'w').close()
    
    js_links, inline_scripts = get_scripts(target_url)

    if not js_links and not inline_scripts:
        print(Fore.YELLOW + "[INFO] Tidak ada file JavaScript atau script inline yang ditemukan.")
        return

    if js_links:
        print(Fore.YELLOW + f"\n[INFO] Menemukan {len(js_links)} file JS eksternal. Memulai scan...")
        for link in js_links:
            try:
                response = requests.get(link, timeout=10, verify=False)
                response.raise_for_status()
                scan_content(link, response.text, output_file)
            except requests.exceptions.RequestException as e:
                print(Fore.RED + f"  [ERROR] Tidak dapat mengambil konten dari {link}: {e}")

    if inline_scripts:
        print(Fore.YELLOW + f"\n[INFO] Menemukan {len(inline_scripts)} script inline. Memulai scan...")
        for i, script_content in enumerate(inline_scripts):
            source_name = f"Script Inline #{i+1} dari {target_url}"
            scan_content(source_name, script_content, output_file)
            
    print(Fore.GREEN + "\n[INFO] Pemindaian selesai.")

if __name__ == "__main__":
    main()
