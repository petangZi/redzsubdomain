# 🕵️‍♂️ redzSubHunter CLI v5
> Ultimate Passive OSINT Subdomain Enumerator & CMS/Port Scanner + REDZ Custom Intelligence

![Banner](https://img.shields.io/badge/REDZ-HUNTER-red?style=for-the-badge&logo=hackaday)  
🔥 All-in-One OSINT CLI tool built for **pentesters, bug bounty hunters**, and digital vigilantes.  
✨ Powered by multiple real-time sources, logic dorking, and smart heuristics — runs smooth even on **Termux Android**.

---

## 🚀 Fitur Unggulan

- 🔎 Multi-source OSINT subdomain enumeration:
  - `crt.sh`, `HackerTarget`, `RapidDNS`, `ThreatCrowd`, `Omnisint`
  - + REDZ-DUMMBER INTELLIGENCE:
    - `Wayback Machine`
    - `Common Crawl`
    - `Zone Transfer (AXFR)`
    - `Reverse DNS`
    - `CSP Header Peek`
    - `Search Engine Dorks` (Google*, Bing, Yahoo, DuckDuckGo)
    - `Custom OSINT Dataset + DNS Bruteforce Permutasi`
- 🧠 Auto detect CMS: `WordPress`, `Laravel`, etc.
- ⚙️ Lightweight port scanner (80, 443, 8080, 8443)
- 📄 Export hasil subdomain aktif + CMS + port ke file
- 📱 100% Termux-compatible – runs on Android!

---

## 📦 Instalasi (Termux/Ubuntu/Debian)

```bash
pkg update && pkg install python git -y
pip install requests dnspython
git clone https://github.com/petangZi/redzsubdomain.git
cd redzsubdomain
python redzhunter.py -d target.com -o hasil.txt
