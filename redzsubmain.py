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
import cloudscraper
import os
from urllib.parse import quote_plus
import base64
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
console = Console()


# 🔧 Konfigurasi akun (HARUS diisi sebelum digunakan)

GITHUB_USERNAME = "your_username"
GITHUB_TOKEN = "your_github_pat"
HEROKU_API_KEY = "your_heroku_api_key"


# ⚠️ Subdomain Takeover Detector

def check_takeover(sub):
    try:
        res = requests.get(f"http://{sub}", timeout=6)
        body = res.text.lower()
        if "github.io" in body or "there isn't a github pages site here" in body:
            auto_claim_github(sub)
            return "✅ Github Pages - Buat repo dengan nama '{}'.github.io' lalu atur CNAME ke subdomain. Sudah dicoba auto-claim."
        if "herokuapp" in body or "no such app" in body:
            return "✅ Heroku - Deploy app baru lalu hubungkan domain di settings. Manual claim."
        if "no such bucket" in body or "bucket does not exist" in body:
            return "✅ AWS S3 - Buat bucket dengan nama subdomain. Manual claim."
        return None
    except:
        return None

# ===============================
# 🚀 Auto Claim Actions
# ===============================
def auto_claim_github(sub):
    repo = sub.replace('.', '-')
    url = f"https://api.github.com/user/repos"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    data = {"name": repo, "auto_init": True}
    try:
        res = requests.post(url, headers=headers, json=data)
        if res.status_code == 201:
            cname_url = f"https://api.github.com/repos/{GITHUB_USERNAME}/{repo}/contents/CNAME"
            cname_data = {
                "content": base64.b64encode(sub.encode()).decode()
            }
            cname_res = requests.put(cname_url, headers=headers, json=cname_data)
            if cname_res.status_code in [201, 200]:
                return True
    except:
        pass
    return False

def auto_claim_heroku(sub):
    try:
        app_name = sub.replace('.', '-')
        url = "https://api.heroku.com/apps"
        headers = {
            "Authorization": f"Bearer {HEROKU_API_KEY}",
            "Accept": "application/vnd.heroku+json; version=3"
        }
        data = {"name": app_name}
        res = requests.post(url, headers=headers, json=data)
        if res.status_code == 201:
            domain_url = f"https://api.heroku.com/apps/{app_name}/domains"
            domain_data = {"hostname": sub}
            requests.post(domain_url, headers=headers, json=domain_data)
            return True
    except:
        pass
    return False

def auto_claim_s3(sub):
    folder = f"claimed_s3/{sub}"
    try:
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "README.txt"), "w") as f:
            f.write("Simulasi S3 Bucket untuk: " + sub)
        return True
    except:
        return False

# ⚠️ CDN Hijack Detector (Basic CNAME Check)

def check_cdn_hijack(sub):
    try:
        answers = dns.resolver.resolve(sub, 'CNAME')
        for rdata in answers:
            cname = str(rdata.target).rstrip('.')
            if any(provider in cname for provider in [
                "github.io", "herokuapp.com", "amazonaws.com",
                "cloudfront.net", "pages.dev", "readthedocs.io"
            ]):
                return cname
    except:
        return None
    return None


# 🌐 Resolver - Multi-bypass

def is_alive(sub):
    resolvers = ['1.1.1.1', '8.8.8.8', '9.9.9.9', '77.88.8.8']
    for resolver_ip in resolvers:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [resolver_ip]
            resolver.resolve(sub, 'A', lifetime=2)
            return True
        except:
            continue
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
    
    try:
        res = requests.get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey", timeout=10)
        if res.status_code == 200:
            for row in res.json()[1:]:
                subs.update(re.findall(rf"[\w.-]+\.{domain}", row[0]))
    except:
        pass

    try:
        res = requests.get(f"http://index.commoncrawl.org/CC-MAIN-2023-40-index?url=*.{domain}&output=json", timeout=10)
        for line in res.text.splitlines():
            subs.update(re.findall(rf"[\w.-]+\.{domain}", line))
    except:
        pass

    try:
        ns = dns.resolver.resolve(domain, 'NS')
        for rdata in ns:
            nsip = str(dns.resolver.resolve(str(rdata.target), 'A')[0])
            z = dns.query.xfr(nsip, domain, timeout=3)
            for msg in z:
                for name in msg.answer:
                    subs.update(str(r.name)[:-1] for r in name.items if str(r.name).endswith(domain + '.'))
    except:
        pass

    try:
        ip = socket.gethostbyname(domain)
        for i in range(1, 255):
            try:
                rev = socket.gethostbyaddr(f"{ip.rsplit('.', 1)[0]}.{i}")[0]
                if domain in rev:
                    subs.add(rev)
            except:
                continue
    except:
        pass

    try:
        scraper = cloudscraper.create_scraper()
        res = scraper.get(f"http://{domain}", timeout=5)
        csp = res.headers.get("Content-Security-Policy", "")
        subs.update(re.findall(rf"[\w.-]+\.{domain}", csp))
    except:
        pass

    engines = [
        f"https://www.bing.com/search?q=site:{domain}+inurl:{domain}",
        f"https://search.yahoo.com/search?p=site:{domain}+inurl:{domain}",
        f"https://duckduckgo.com/html/?q=site:{domain}+inurl:{domain}"
    ]
    headers = {"User-Agent": "Mozilla/5.0"}
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

    return list(subs)


# ===============================
# 🚀 Main
# ===============================
def main():
    parser = argparse.ArgumentParser(description="🔍 redzSubHunter CLI v8 - AUTO CLAIM + OSINT + CMS + PORT + Takeover")
    parser.add_argument("-d", "--domain", required=True, help="Target domain, contoh: kemdikbud.go.id")
    parser.add_argument("-o", "--output", help="Output file (default: hasil.txt)", default="hasil.txt")
    args = parser.parse_args()

    domain = args.domain
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

    console.print(f"\n[bold green]🎯 TOTAL:[/] {len(found)} SUBDOMAIN (Aktif + CMS + Port + CNAME)\n")

    alive = []
    with open(args.output, "w") as f:
        for sub in sorted(found):
            status = []
            takeover_guide = ""
            if is_alive(sub):
                cms = detect_cms(sub)
                ports = scan_ports(sub)
                cname = check_cdn_hijack(sub)
                takeover = check_takeover(sub)
                if takeover:
                    status.append("[red]POTENSI TAKEOVER[/]")
                    takeover_guide = f" --> {takeover}"
                console.print(f"[✅] {sub} | CMS: [yellow]{cms}[/] | Port: [blue]{ports}[/] | CNAME: {cname or '-'} {' '.join(status)}")
                f.write(f"{sub} | CMS: {cms} | Port: {ports} | CNAME: {cname or '-'} | {' '.join(status)}{takeover_guide}\n")
                alive.append(sub)
            else:
                console.print(f"[❌] {sub}")

    console.print(f"\n[bold magenta]📦 DISIMPAN:[/] {args.output} | Subdomain aktif: {len(alive)}")

if __name__ == "__main__":
    main()
