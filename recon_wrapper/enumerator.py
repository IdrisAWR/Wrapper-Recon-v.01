"""
=====================================================================
  Automated Recon Wrapper - Subdomain Enumerator
  Menggabungkan 3 teknik:
    1. Passive OSINT  → crt.sh  (Certificate Transparency)
    2. Passive OSINT  → HackerTarget HostSearch API
    3. Active Bruteforce → DNS resolution dari wordlist
=====================================================================
"""

import asyncio
import json
import re
import socket
from typing import Set, List, Optional
from urllib.parse import urlparse

import aiohttp
import dns.resolver
import dns.exception

from .config import (
    BUILTIN_WORDLIST,
    CRTSH_URL,
    HACKERTARGET_URL,
    DNS_TIMEOUT,
    DNS_LIFETIME,
    DEFAULT_CONCURRENCY,
)
from .logger import ReconLogger


# ─────────────────────────────────────────────────────────────────
#  Helper: clean & validate subdomain string
# ─────────────────────────────────────────────────────────────────
_SUBDOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def _clean_subdomain(raw: str, domain: str) -> Optional[str]:
    """Bersihkan dan validasi string subdomain."""
    raw = raw.strip().lower().lstrip("*.")
    if not raw:
        return None
    if not raw.endswith(f".{domain}") and raw != domain:
        return None
    if not _SUBDOMAIN_RE.match(raw):
        return None
    return raw


# ─────────────────────────────────────────────────────────────────
#  DNS Resolver (async wrapper via run_in_executor)
# ─────────────────────────────────────────────────────────────────
def _resolve_sync(hostname: str) -> Optional[str]:
    """Resolve hostname ke IP (sync, dijalankan di executor)."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout  = DNS_TIMEOUT
        resolver.lifetime = DNS_LIFETIME
        answers = resolver.resolve(hostname, "A")
        return str(answers[0])
    except Exception:
        return None


async def _resolve_async(hostname: str, loop: asyncio.AbstractEventLoop) -> Optional[str]:
    return await loop.run_in_executor(None, _resolve_sync, hostname)


# ─────────────────────────────────────────────────────────────────
#  SOURCE 1: crt.sh (Certificate Transparency)
# ─────────────────────────────────────────────────────────────────
async def _fetch_crtsh(
    session: aiohttp.ClientSession,
    domain: str,
    log: ReconLogger,
) -> Set[str]:
    results: Set[str] = set()
    url = CRTSH_URL.replace("{domain}", domain)
    log.debug(f"[crt.sh] GET {url}")
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status == 200:
                text = await resp.text()
                data = json.loads(text)
                for entry in data:
                    for field in ("name_value", "common_name"):
                        value = entry.get(field, "")
                        for sub in value.split("\n"):
                            cleaned = _clean_subdomain(sub, domain)
                            if cleaned:
                                results.add(cleaned)
                log.debug(f"[crt.sh] ditemukan {len(results)} subdomain mentah")
    except Exception as exc:
        log.warning(f"[crt.sh] gagal: {exc}")
    return results


# ─────────────────────────────────────────────────────────────────
#  SOURCE 2: HackerTarget HostSearch
# ─────────────────────────────────────────────────────────────────
async def _fetch_hackertarget(
    session: aiohttp.ClientSession,
    domain: str,
    log: ReconLogger,
) -> Set[str]:
    results: Set[str] = set()
    url = HACKERTARGET_URL.replace("{domain}", domain)
    log.debug(f"[HackerTarget] GET {url}")
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            if resp.status == 200:
                text = await resp.text()
                if "error" in text.lower() or "API count" in text:
                    log.warning("[HackerTarget] rate-limit atau error API")
                    return results
                for line in text.splitlines():
                    parts = line.split(",")
                    if parts:
                        cleaned = _clean_subdomain(parts[0], domain)
                        if cleaned:
                            results.add(cleaned)
                log.debug(f"[HackerTarget] ditemukan {len(results)} subdomain mentah")
    except Exception as exc:
        log.warning(f"[HackerTarget] gagal: {exc}")
    return results


# ─────────────────────────────────────────────────────────────────
#  SOURCE 3: DNS Bruteforce dari wordlist
# ─────────────────────────────────────────────────────────────────
async def _bruteforce_dns(
    domain: str,
    wordlist: List[str],
    concurrency: int,
    log: ReconLogger,
) -> Set[str]:
    """Resolve setiap kata dari wordlist sebagai subdomain."""
    found: Set[str] = set()
    loop = asyncio.get_event_loop()
    sem  = asyncio.Semaphore(concurrency)

    async def _check(word: str) -> None:
        hostname = f"{word}.{domain}"
        async with sem:
            ip = await _resolve_async(hostname, loop)
            if ip:
                found.add(hostname)
                log.debug(f"[bruteforce] {hostname} → {ip}")

    log.info(f"Memulai DNS bruteforce dengan {len(wordlist)} kata ...")
    tasks = [asyncio.create_task(_check(w)) for w in wordlist]
    await asyncio.gather(*tasks)
    return found


# ─────────────────────────────────────────────────────────────────
#  PUBLIC: SubdomainEnumerator
# ─────────────────────────────────────────────────────────────────
class SubdomainEnumerator:
    """
    Enumerasi subdomain dari berbagai sumber lalu resolve DNS-nya.

    Parameters
    ----------
    domain      : target domain (misal: example.com)
    wordlist    : list kata tambahan untuk bruteforce (None = builtin)
    concurrency : jumlah coroutine bersamaan untuk bruteforce
    passive_only: True → lewati bruteforce DNS
    verbose     : tampilkan debug log
    """

    def __init__(
        self,
        domain: str,
        wordlist: Optional[List[str]] = None,
        concurrency: int = DEFAULT_CONCURRENCY,
        passive_only: bool = False,
        verbose: bool = False,
    ):
        self.domain       = domain.lower().strip()
        self.wordlist     = wordlist if wordlist else BUILTIN_WORDLIST
        self.concurrency  = concurrency
        self.passive_only = passive_only
        self.log          = ReconLogger(verbose=verbose)

    async def run(self) -> List[dict]:
        """
        Jalankan semua sumber enumerasi.
        Return list of {"subdomain": str, "ip": str|None, "source": str}
        """
        self.log.section("FASE 1 — Subdomain Enumeration")
        self.log.info(f"Target domain : {self.domain}")

        raw_subdomains: Set[str] = {self.domain}

        headers = {
            "User-Agent": "ReconWrapper/1.0 (https://github.com/recon-wrapper)",
            "Accept": "application/json, text/plain, */*",
        }

        async with aiohttp.ClientSession(headers=headers) as session:
            # Passive sources (paralel)
            self.log.info("Menjalankan passive OSINT (crt.sh + HackerTarget) ...")
            passive_tasks = [
                _fetch_crtsh(session, self.domain, self.log),
                _fetch_hackertarget(session, self.domain, self.log),
            ]
            passive_results = await asyncio.gather(*passive_tasks)
            for result_set in passive_results:
                raw_subdomains.update(result_set)

        self.log.success(
            f"Passive OSINT selesai — {len(raw_subdomains)} subdomain unik ditemukan"
        )

        # Active bruteforce
        if not self.passive_only:
            brute_results = await _bruteforce_dns(
                self.domain, self.wordlist, self.concurrency, self.log
            )
            raw_subdomains.update(brute_results)

        self.log.success(
            f"Total subdomain unik (sebelum resolve): {len(raw_subdomains)}"
        )

        # Resolve semua ke IP
        self.log.info("Meresolve semua subdomain ke alamat IP ...")
        loop  = asyncio.get_event_loop()
        sem   = asyncio.Semaphore(self.concurrency)
        resolved: List[dict] = []

        async def _resolve_entry(sub: str) -> None:
            async with sem:
                ip = await _resolve_async(sub, loop)
                source = "bruteforce" if sub not in {self.domain} else "passive"
                resolved.append({
                    "subdomain": sub,
                    "ip"       : ip,
                    "resolved" : ip is not None,
                    "source"   : source,
                })
                if ip:
                    self.log.found(sub, ip)

        tasks = [asyncio.create_task(_resolve_entry(s)) for s in raw_subdomains]
        await asyncio.gather(*tasks)

        alive_count = sum(1 for r in resolved if r["resolved"])
        self.log.success(
            f"Resolve selesai — {alive_count}/{len(resolved)} subdomain berhasil diresolve"
        )

        return resolved
