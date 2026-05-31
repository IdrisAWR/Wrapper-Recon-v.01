# Automated Recon Wrapper 🔍

**Tool Python untuk Automated Subdomain Enumeration + HTTP Probing + JSON Report**

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## 🚀 Fitur Utama

| Fitur | Keterangan |
|---|---|
| **Passive OSINT** | Ambil subdomain dari crt.sh (Certificate Transparency) & HackerTarget |
| **DNS Bruteforce** | Resolve subdomain dari wordlist secara async |
| **HTTP Probing** | Cek HTTP/HTTPS, kumpulkan status code, title, server, redirect chain |
| **JSON Report** | Laporan lengkap terstruktur siap diproses otomatis |
| **Text Summary** | Ringkasan human-readable di terminal & file `.txt` |
| **Async & Cepat** | Menggunakan `asyncio` + `aiohttp` — bisa 50-100 request bersamaan |
| **Rich UI** | Output terminal berwarna dengan tabel interaktif |

---

## 📁 Struktur Project

```
NyobaBuatTools/
├── recon.py                    # Entry point utama (CLI)
├── requirements.txt            # Dependensi Python
├── wordlist_example.txt        # Contoh custom wordlist
└── recon_wrapper/
    ├── __init__.py
    ├── config.py               # Konfigurasi & konstanta
    ├── logger.py               # Rich-based logger
    ├── enumerator.py           # Subdomain enumerator (3 sumber)
    ├── prober.py               # HTTP prober async
    └── reporter.py             # JSON + text report generator
```

---

## 🛠️ Instalasi

```bash
# 1. Clone folder project
git clone https://github.com/IdrisAWR/Wrapper-Recon-v.01.git

# 2. Install dependensi
pip install -r requirements.txt
```

**Dependensi:**
- `aiohttp` — HTTP async client
- `dnspython` — DNS resolver
- `rich` — terminal UI & tabel
- `requests` — HTTP sync (fallback)
- `colorama` — warna terminal Windows
- `tqdm` — progress bar

---

## 🎯 Cara Penggunaan

### Scan Dasar
```bash
python recon.py -d example.com
```

### Hanya Passive OSINT (tanpa bruteforce)
```bash
python recon.py -d example.com --passive-only
```

### Dengan Custom Wordlist
```bash
python recon.py -d example.com -w wordlist_example.txt
```

### Output ke Direktori Kustom
```bash
python recon.py -d example.com -o ./hasil_recon
```

### Atur Timeout & Concurrency
```bash
python recon.py -d example.com --timeout 15 --concurrency 80
```

### Hanya HTTPS
```bash
python recon.py -d example.com --schemes https
```

### Mode Verbose (debug)
```bash
python recon.py -d example.com --verbose
```

### Semua Opsi Sekaligus
```bash
python recon.py \
  -d example.com \
  -w wordlist_example.txt \
  -o ./hasil \
  --timeout 10 \
  --concurrency 80 \
  --schemes https http \
  --retries 3 \
  --verbose
```

---

## 📊 Format Laporan JSON

```json
{
  "meta": {
    "tool": "Automated Recon Wrapper",
    "version": "1.0.0",
    "target_domain": "example.com",
    "scan_timestamp": "2026-05-30T13:00:00+00:00",
    "output_dir": "/path/to/output"
  },
  "statistics": {
    "total_subdomains": 42,
    "resolved_subdomains": 35,
    "unresolved_subdomains": 7,
    "live_hosts": 18,
    "dead_hosts": 17,
    "live_rate_percent": 51.43,
    "status_code_distribution": { "200": 12, "301": 4, "403": 2 },
    "server_distribution": { "nginx": 10, "Apache": 5 },
    "risk_distribution": { "accessible": 12, "redirect": 4, "forbidden": 2 },
    "interesting_hosts": [
      {
        "url": "https://admin.example.com",
        "status": 200,
        "title": "Admin Panel",
        "server": "nginx",
        "ip": "93.184.216.34"
      }
    ]
  },
  "subdomains": [ ... ],
  "http_probes": [ ... ]
}
```

---

## 🔒 Disclaimer

> Tool ini dibuat untuk **tujuan edukasi dan pengujian keamanan yang sah** (authorized penetration testing). 
> Jangan gunakan pada target tanpa izin eksplisit. Penggunaan ilegal sepenuhnya tanggung jawab pengguna.

---

## 📝 Argumen CLI Lengkap

```
usage: recon.py [-h] -d DOMAIN [-w FILE] [--passive-only]
                [--timeout DETIK] [--concurrency N]
                [--schemes SCHEME [SCHEME ...]] [--retries N]
                [-o DIR] [-v] [--version]

Target (wajib):
  -d, --domain DOMAIN       Domain target, contoh: example.com

Pengaturan Enumerasi:
  -w, --wordlist FILE        Path ke file wordlist custom
  --passive-only             Hanya passive OSINT, tanpa DNS bruteforce

Pengaturan HTTP Probe:
  --timeout DETIK            Timeout per request (default: 8)
  --concurrency N            Coroutine paralel (default: 50)
  --schemes SCHEME           Skema yang diuji: https, http
  --retries N                Retry jika gagal (default: 2)

Output:
  -o, --output DIR           Direktori output (default: recon_results)

Misc:
  -v, --verbose              Tampilkan log debug
  --version                  Tampilkan versi
```
