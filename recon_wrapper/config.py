"""
=====================================================================
  Automated Recon Wrapper - Core Configuration
  Centralized settings dan konstanta untuk seluruh tool
=====================================================================
"""

import os

# ─────────────────────────────────────────────────────────────────
#  NETWORK SETTINGS
# ─────────────────────────────────────────────────────────────────
DEFAULT_TIMEOUT       = 8          # detik per request HTTP
DEFAULT_CONCURRENCY   = 50         # jumlah coroutine async bersamaan
DEFAULT_RETRIES       = 2          # retry jika koneksi gagal
DNS_TIMEOUT           = 5          # timeout DNS resolve
DNS_LIFETIME          = 10         # lifetime total query DNS

# ─────────────────────────────────────────────────────────────────
#  HTTP PROBING
# ─────────────────────────────────────────────────────────────────
HTTP_SCHEMES          = ["https", "http"]
FOLLOW_REDIRECTS      = True
MAX_REDIRECTS         = 5

# Status code yang dianggap "aktif / live"
LIVE_STATUS_CODES     = list(range(100, 600))   # semua; filter di laporan
INTERESTING_CODES     = [200, 201, 204, 301, 302, 307, 308, 401, 403, 404, 500]

# ─────────────────────────────────────────────────────────────────
#  SUBDOMAIN ENUMERATION
# ─────────────────────────────────────────────────────────────────
# Wordlist bawaan (built-in fallback)
BUILTIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "remote",
    "blog", "shop", "store", "api", "dev", "staging", "test", "admin",
    "portal", "app", "apps", "cdn", "media", "static", "assets", "img",
    "images", "video", "download", "uploads", "files", "docs", "wiki",
    "support", "help", "kb", "forum", "community", "chat", "meet",
    "vpn", "ssh", "rdp", "ns1", "ns2", "dns", "mx", "mx1", "mx2",
    "gateway", "proxy", "lb", "load", "internal", "intranet", "corp",
    "office", "backup", "bak", "old", "new", "secure", "ssl", "auth",
    "login", "sso", "oauth", "git", "gitlab", "github", "jenkins",
    "ci", "cd", "monitor", "grafana", "kibana", "elastic", "search",
    "redis", "db", "database", "mysql", "postgres", "mongo", "api2",
    "v1", "v2", "beta", "alpha", "preview", "sandbox", "demo",
    "status", "health", "ping", "analytics", "tracking", "metrics",
    "mobile", "m", "wap", "pwa", "spa", "micro", "service", "ws",
    "websocket", "stream", "live", "feed", "rss", "atom", "sitemap",
]

# Public DNS-over-HTTPS Certificate Transparency APIs
CRTSH_URL  = "https://crt.sh/?q=%.{domain}&output=json"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"

# ─────────────────────────────────────────────────────────────────
#  OUTPUT
# ─────────────────────────────────────────────────────────────────
DEFAULT_OUTPUT_DIR    = "recon_results"
REPORT_FILENAME       = "recon_report_{domain}_{timestamp}.json"
SUMMARY_FILENAME      = "summary_{domain}_{timestamp}.txt"

# ─────────────────────────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────────────────────────
BANNER = r"""
+============================================================+
|                                                            |
|   ____  _____ ____ ___  _   _   __        _____ ____       |
|  |  _ \| ____/ ___/ _ \| \ | | \ \      / /  _ \___ \      |
|  | |_) |  _|| |  | | | |  \| |  \ \ /\ / /| |_) |__) |     |
|  |  _ <| |__| |__| |_| | |\  |   \ V  V / |  _ </ __/      |
|  |_| \_|_____\____\___/|_| \_|    \_/\_/  |_| \_\_____|    |
|                                                            |
|       Automated Recon Wrapper v1.0.0 By AwR                |
|       Subdomain Enum + HTTP Probing + JSON Report          |
|                                                            |
+============================================================+
"""
