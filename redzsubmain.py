import requests
import argparse
import dns.resolver
import dns.query
import dns.zone
import time
import re
import socket
import subprocess
import itertools
from urllib.parse import quote_plus
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn

console = Console()


#  Resolver - Cek aktif gak
def is_alive(sub):
    try:
        dns.resolver.resolve(sub, 'A')
        return True
    except:
        return False


# 🧠 CMS Detector (WordPress, Laravel)

def detect_cms(sub):
    try:
        res = requests.get(f"http://{sub}", timeout=5)
        html = res.text.lower()
        if 'wp-content' in html or 'wordpress' in html:
            return "WordPress"
        elif '/laravel' in html or 'laravel_session' in res.headers.get('Set-Cookie', ''):
            return "Laravel"
        else:
            return "-"
    except:
        return "-"
# 🔧 Port Scanner (ringan)
def scan_ports(sub, ports=[80, 443, 8080, 8443]):
    open_ports = []
    for port in ports:
        try:
            sock = socket.create_connection((sub, port), timeout=2)
            open_ports.append(port)
            sock.close()
        except:
            continue
    return open_ports
#  Source 1: crt.sh
def get_from_crtsh(domain):
    try:
        res = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=10)
        data = res.json()
        subs = set()
        for entry in data:
            for sub in entry['name_value'].split('\n'):
                if domain in sub:
                    subs.add(sub.strip())
        return list(subs)
    except:
        return []


#  Source 2: HackerTarget

def get_from_hackertarget(domain):
    try:
        res = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
        return [line.split(',')[0] for line in res.text.splitlines() if domain in line]
    except:
        return []


#  Source 3: RapidDNS

def get_from_rapiddns(domain):
    try:
        res = requests.get(f"https://rapiddns.io/subdomain/{domain}?full=1#result", timeout=10)
        return list(set(re.findall(rf"[\w.-]+\.{domain}", res.text)))
    except:
        return []


#  Source 4: ThreatCrowd

def get_from_threatcrowd(domain):
    try:
        res = requests.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}", timeout=10)
        data = res.json()
        return data.get("subdomains", [])
    except:
        return []


#  Source 5: Omnisint (sonar.omnisint.io)

def get_from_omnisint(domain):
    try:
        res = requests.get(f"https://sonar.omnisint.io/subdomains/{domain}", timeout=10)
        if res.status_code == 200:
            return res.json()
        return []
    except:
        return []


#  Source 6: REDZ Source (Custom Dictionary Brute)
def get_from_redzdummber(domain):
    subs = set()
    console.log("[bold cyan]+[/] REDZ custom brute source...")
    start = time.time()

    # Wayback Machine (Fast)
    try:
        res = requests.get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey", timeout=10)
        if res.status_code == 200:
            for row in res.json()[1:]:
                subs.update(re.findall(rf"[\w.-]+\.{domain}", row[0]))
    except:
        pass

    # Common Crawl (partial/faster)
    try:
        res = requests.get(f"http://index.commoncrawl.org/CC-MAIN-2023-40-index?url=*.{domain}&output=json", timeout=8)
        for line in res.text.splitlines()[:50]:
            subs.update(re.findall(rf"[\w.-]+\.{domain}", line))
    except:
        pass

    # DNS Zone Transfer
    try:
        ns = dns.resolver.resolve(domain, 'NS')
        for rdata in ns:
            nsip = str(dns.resolver.resolve(str(rdata.target), 'A')[0])
            z = dns.query.xfr(nsip, domain, timeout=2)
            for msg in z:
                for name in msg.answer:
                    subs.update(str(r.name)[:-1] for r in name.items if str(r.name).endswith(domain + '.'))
    except:
        pass

    # Reverse DNS (limit)
    try:
        ip = socket.gethostbyname(domain)
        for i in range(1, 51):
            try:
                rev = socket.gethostbyaddr(f"{ip.rsplit('.', 1)[0]}.{i}")[0]
                if domain in rev:
                    subs.add(rev)
            except:
                continue
    except:
        pass

    # CSP Header Peek
    try:
        res = requests.get(f"http://{domain}", timeout=5)
        csp = res.headers.get("Content-Security-Policy", "")
        subs.update(re.findall(rf"[\w.-]+\.{domain}", csp))
    except:
        pass

    # Search Engine Dorks
    engines = [
        f"https://duckduckgo.com/html/?q=site:{domain}+inurl:{domain}",
        f"https://www.google.com/search?q=site:{domain}+inurl:{domain}"
    ]
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/112.0.0.0 Safari/537.36"}
    for engine in engines:
        try:
            res = requests.get(engine, headers=headers, timeout=10)
            subs.update(re.findall(rf"[\w.-]+\.{domain}", res.text))
        except:
            continue

    for word in ['dev', 'test', 'mail', 'vpn', 'cpanel', 'admin']:
        subs.add(f"{word}.{domain}")

    for prefix in ['a', 'b', 'c', 'x', 'z']:
        for suffix in ['1', '2', 'dev', 'beta']:
            subs.add(f"{prefix}{suffix}.{domain}")

    base = list(subs)
    for sub in base:
        s = sub.split('.')[0]
        parts = re.split('[-_]', s)
        if len(parts) > 1:
            for perm in itertools.permutations(parts):
                subs.add(f"{'-'.join(perm)}.{domain}")

    console.log(f"[🧠] redzdummber selesai dalam {round(time.time()-start,2)} detik")
    return list(subs)

# ===============================
# 🚀 Main
# ===============================
def main():
    parser = argparse.ArgumentParser(description="🔍 redzSubHunter CLI v5 - OSINT + CMS + Port + REDZ Dummber")
    parser.add_argument("-d", "--domain", required=True, help="Target domain, contoh: kemdikbud.go.id")
    parser.add_argument("-o", "--output", help="Output file (default: hasil.txt)", default="hasil.txt")
    args = parser.parse_args()

    domain = args.domain.replace("https://", "").replace("http://", "").strip("/")
    console.print(f"\n[bold cyan]🧠 SCANNING SEMUA SOURCES UNTUK:[/] {domain}\n")

    found = set()
    sources = [
        ("crt.sh", get_from_crtsh),
        ("hackertarget", get_from_hackertarget),
        ("rapiddns", get_from_rapiddns),
        ("threatcrowd", get_from_threatcrowd),
        ("omnisint", get_from_omnisint),
        ("redzdummber", get_from_redzdummber)
    ]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[green]Mengumpulkan subdomain...", total=len(sources))
        for name, func in sources:
            console.log(f"[+] {name} ...")
            found.update(func(domain))
            progress.advance(task)

    console.print(f"\n[bold green]🎯 TOTAL:[/] {len(found)} SUBDOMAIN (Aktif + CMS + Port)\n")

    alive = []
    with open(args.output, "w") as f:
        for sub in sorted(found):
            if is_alive(sub):
                cms = detect_cms(sub)
                ports = scan_ports(sub)
                console.print(f"[✅] {sub} | CMS: [yellow]{cms}[/] | Port: [blue]{ports}[/]")
                f.write(f"{sub} | CMS: {cms} | Port: {ports}\n")
                alive.append(sub)
            else:
                console.print(f"[❌] {sub}")

    console.print(f"\n[bold magenta]📦 DISIMPAN:[/] {args.output} | Subdomain aktif: {len(alive)}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        console.print(f"[bold red]🔥 ERROR:[/] {e}")
