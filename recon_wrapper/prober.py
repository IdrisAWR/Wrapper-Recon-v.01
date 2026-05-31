"""
=====================================================================
  Automated Recon Wrapper - HTTP Prober
  Mengecek setiap subdomain melalui HTTP/HTTPS, mengumpulkan:
    - Status code
    - Title halaman
    - Server header
    - Content-Type
    - Redirect chain
    - Response time
    - TLS/SSL info (untuk HTTPS)
=====================================================================
"""

import asyncio
import re
import ssl
import time
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

import aiohttp
from aiohttp import ClientConnectorError, ClientResponseError, ServerDisconnectedError

from .config import (
    HTTP_SCHEMES,
    DEFAULT_TIMEOUT,
    DEFAULT_CONCURRENCY,
    DEFAULT_RETRIES,
    MAX_REDIRECTS,
)
from .logger import ReconLogger


# ─────────────────────────────────────────────────────────────────
#  Helper: extract <title> dari HTML
# ─────────────────────────────────────────────────────────────────
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _extract_title(html: str) -> str:
    match = _TITLE_RE.search(html)
    if match:
        title = match.group(1).strip()
        # hapus newline dan spasi berlebih
        title = re.sub(r"\s+", " ", title)
        return title[:200]
    return ""


# ─────────────────────────────────────────────────────────────────
#  Helper: hitung kategori risiko berdasarkan status code
# ─────────────────────────────────────────────────────────────────
def _risk_tag(status: int) -> str:
    if status in (200, 201, 204):
        return "accessible"
    elif status in (301, 302, 307, 308):
        return "redirect"
    elif status == 401:
        return "auth_required"
    elif status == 403:
        return "forbidden"
    elif status == 404:
        return "not_found"
    elif status == 429:
        return "rate_limited"
    elif 500 <= status < 600:
        return "server_error"
    else:
        return "other"


# ─────────────────────────────────────────────────────────────────
#  Single subdomain probe
# ─────────────────────────────────────────────────────────────────
async def _probe_single(
    session  : aiohttp.ClientSession,
    url      : str,
    timeout  : int,
    retries  : int,
    log      : ReconLogger,
) -> Optional[Dict[str, Any]]:
    """
    Probe satu URL — kembalikan dict hasil atau None jika gagal.
    """
    for attempt in range(retries + 1):
        try:
            start = time.monotonic()
            async with session.get(
                url,
                timeout         = aiohttp.ClientTimeout(total=timeout),
                allow_redirects = True,
                max_redirects   = MAX_REDIRECTS,
                ssl             = False,           # abaikan SSL error, kita rekam saja
            ) as resp:
                elapsed_ms = int((time.monotonic() - start) * 1000)

                # Baca sebagian body untuk title extraction
                try:
                    body = await resp.text(encoding="utf-8", errors="replace")
                except Exception:
                    body = ""

                title   = _extract_title(body)
                server  = resp.headers.get("Server", "")
                ctype   = resp.headers.get("Content-Type", "").split(";")[0].strip()
                powered = resp.headers.get("X-Powered-By", "")

                # Redirect chain
                history = [str(h.url) for h in resp.history]

                result = {
                    "url"           : url,
                    "final_url"     : str(resp.url),
                    "status_code"   : resp.status,
                    "risk_tag"      : _risk_tag(resp.status),
                    "title"         : title,
                    "server"        : server,
                    "content_type"  : ctype,
                    "x_powered_by"  : powered,
                    "response_ms"   : elapsed_ms,
                    "redirect_chain": history,
                    "redirected"    : len(history) > 0,
                    "content_length": resp.headers.get("Content-Length", ""),
                    "headers"       : dict(resp.headers),
                }

                log.debug(f"[probe] {url} → {resp.status} ({elapsed_ms}ms)")
                return result

        except (ClientConnectorError, asyncio.TimeoutError, ServerDisconnectedError,
                ConnectionResetError, OSError) as exc:
            log.debug(f"[probe] {url} attempt {attempt+1} gagal: {type(exc).__name__}")
            if attempt < retries:
                await asyncio.sleep(0.5 * (attempt + 1))
            continue
        except Exception as exc:
            log.debug(f"[probe] {url} error tak terduga: {exc}")
            break

    return None


# ─────────────────────────────────────────────────────────────────
#  PUBLIC: HttpProber
# ─────────────────────────────────────────────────────────────────
class HttpProber:
    """
    Validasi HTTP/HTTPS untuk daftar subdomain.

    Parameters
    ----------
    subdomains   : list dict dari SubdomainEnumerator (harus resolved=True)
    timeout      : timeout per request (detik)
    concurrency  : jumlah request bersamaan
    retries      : jumlah retry per URL
    schemes      : urutan skema yang dicoba (["https", "http"])
    verbose      : tampilkan debug log
    """

    def __init__(
        self,
        subdomains  : List[dict],
        timeout     : int = DEFAULT_TIMEOUT,
        concurrency : int = DEFAULT_CONCURRENCY,
        retries     : int = DEFAULT_RETRIES,
        schemes     : List[str] = None,
        verbose     : bool = False,
    ):
        # Hanya probe yang berhasil diresolve
        self.targets     = [s for s in subdomains if s.get("resolved")]
        self.timeout     = timeout
        self.concurrency = concurrency
        self.retries     = retries
        self.schemes     = schemes if schemes else HTTP_SCHEMES
        self.log         = ReconLogger(verbose=verbose)

    async def run(self) -> List[dict]:
        """
        Probe semua target. Return list hasil probe lengkap.
        """
        self.log.section("FASE 2 — HTTP Probing")
        self.log.info(
            f"Memulai HTTP probe untuk {len(self.targets)} host "
            f"(timeout={self.timeout}s, concurrency={self.concurrency})"
        )

        sem     = asyncio.Semaphore(self.concurrency)
        results : List[dict] = []

        # SSL context yang permisif
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode    = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(
            ssl            = ssl_ctx,
            limit          = self.concurrency,
            limit_per_host = 2,
            enable_cleanup_closed = True,
        )

        headers = {
            "User-Agent" : (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept"          : "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language" : "en-US,en;q=0.9",
            "Connection"      : "keep-alive",
        }

        async with aiohttp.ClientSession(
            connector = connector,
            headers   = headers,
        ) as session:

            async def _probe_host(entry: dict) -> None:
                subdomain = entry["subdomain"]
                host_result = {
                    "subdomain" : subdomain,
                    "ip"        : entry.get("ip"),
                    "source"    : entry.get("source"),
                    "probes"    : [],
                    "live"      : False,
                    "best_url"  : None,
                    "best_status": None,
                }

                async with sem:
                    for scheme in self.schemes:
                        url = f"{scheme}://{subdomain}"
                        probe = await _probe_single(
                            session, url, self.timeout, self.retries, self.log
                        )
                        if probe:
                            host_result["probes"].append(probe)
                            if not host_result["live"]:
                                # Pertama yang berhasil = "best"
                                host_result["live"]        = True
                                host_result["best_url"]    = probe["final_url"]
                                host_result["best_status"] = probe["status_code"]
                                host_result["best_title"]  = probe.get("title", "")
                                host_result["best_server"] = probe.get("server", "")
                            # Jika sudah live dari HTTPS, skip HTTP
                            if scheme == "https":
                                break

                if host_result["live"]:
                    self.log.live(
                        host_result["best_url"],
                        host_result["best_status"],
                        host_result.get("best_title", ""),
                        host_result.get("best_server", ""),
                    )
                else:
                    self.log.dead(subdomain, "no response on HTTP/HTTPS")

                results.append(host_result)

            tasks = [asyncio.create_task(_probe_host(t)) for t in self.targets]
            await asyncio.gather(*tasks)

        live_count = sum(1 for r in results if r["live"])
        self.log.success(
            f"HTTP probe selesai — {live_count}/{len(results)} host aktif"
        )
        return results
