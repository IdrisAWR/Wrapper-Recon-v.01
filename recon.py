"""
=====================================================================
  Automated Recon Wrapper - Main Entry Point
  CLI yang merangkai semua fase:
    1. Subdomain Enumeration
    2. HTTP Probing
    3. JSON Report Generation
=====================================================================

Contoh penggunaan:
    python recon.py -d example.com
    python recon.py -d example.com --passive-only --verbose
    python recon.py -d example.com -w wordlist.txt -o ./output --timeout 10
    python recon.py -d example.com --concurrency 100 --schemes https
"""

import argparse
import asyncio
import sys
import os
import time
from pathlib import Path
from typing import List, Optional

# Pastikan recon_wrapper bisa diimport
sys.path.insert(0, str(Path(__file__).parent))

from recon_wrapper.config    import BANNER, DEFAULT_OUTPUT_DIR, DEFAULT_TIMEOUT, DEFAULT_CONCURRENCY
from recon_wrapper.logger    import ReconLogger, console
from recon_wrapper.enumerator import SubdomainEnumerator
from recon_wrapper.prober    import HttpProber
from recon_wrapper.reporter  import ReportGenerator

from rich.panel import Panel
from rich.text  import Text


# ─────────────────────────────────────────────────────────────────
#  CLI Argument Parser
# ─────────────────────────────────────────────────────────────────
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog        = "recon.py",
        description = "Automated Recon Wrapper — Subdomain Enum + HTTP Probe + JSON Report",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = """
Contoh:
  python recon.py -d example.com
  python recon.py -d example.com --passive-only
  python recon.py -d example.com -w wordlist.txt --timeout 15
  python recon.py -d example.com --schemes https --concurrency 80
  python recon.py -d example.com -o ./my_results --verbose
        """,
    )

    # ── Target ──────────────────────────────────────────────────
    required = parser.add_argument_group("Target (wajib)")
    required.add_argument(
        "-d", "--domain",
        required = True,
        metavar  = "DOMAIN",
        help     = "Domain target, contoh: example.com",
    )

    # ── Enumerasi ───────────────────────────────────────────────
    enum_group = parser.add_argument_group("Pengaturan Enumerasi")
    enum_group.add_argument(
        "-w", "--wordlist",
        metavar = "FILE",
        default = None,
        help    = "Path ke file wordlist (satu kata per baris). Default: wordlist bawaan.",
    )
    enum_group.add_argument(
        "--passive-only",
        action  = "store_true",
        default = False,
        help    = "Hanya gunakan sumber pasif (crt.sh + HackerTarget), tanpa DNS bruteforce.",
    )

    # ── HTTP Probe ───────────────────────────────────────────────
    probe_group = parser.add_argument_group("Pengaturan HTTP Probe")
    probe_group.add_argument(
        "--timeout",
        type    = int,
        default = DEFAULT_TIMEOUT,
        metavar = "DETIK",
        help    = f"Timeout per HTTP request (default: {DEFAULT_TIMEOUT}s).",
    )
    probe_group.add_argument(
        "--concurrency",
        type    = int,
        default = DEFAULT_CONCURRENCY,
        metavar = "N",
        help    = f"Jumlah coroutine paralel (default: {DEFAULT_CONCURRENCY}).",
    )
    probe_group.add_argument(
        "--schemes",
        nargs   = "+",
        default = ["https", "http"],
        choices = ["https", "http"],
        metavar = "SCHEME",
        help    = "Skema yang diuji (default: https http).",
    )
    probe_group.add_argument(
        "--retries",
        type    = int,
        default = 2,
        metavar = "N",
        help    = "Jumlah retry jika koneksi gagal (default: 2).",
    )

    # ── Output ───────────────────────────────────────────────────
    out_group = parser.add_argument_group("Output")
    out_group.add_argument(
        "-o", "--output",
        default = DEFAULT_OUTPUT_DIR,
        metavar = "DIR",
        help    = f"Direktori output (default: {DEFAULT_OUTPUT_DIR}).",
    )

    # ── Misc ─────────────────────────────────────────────────────
    parser.add_argument(
        "-v", "--verbose",
        action  = "store_true",
        default = False,
        help    = "Tampilkan log debug detail.",
    )
    parser.add_argument(
        "--version",
        action  = "version",
        version = "Automated Recon Wrapper v1.0.0",
    )

    return parser


# ─────────────────────────────────────────────────────────────────
#  Load custom wordlist dari file
# ─────────────────────────────────────────────────────────────────
def _load_wordlist(path: str) -> List[str]:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File wordlist tidak ditemukan: {path}")
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    return words


# ─────────────────────────────────────────────────────────────────
#  Async Main Pipeline
# ─────────────────────────────────────────────────────────────────
async def _run_pipeline(args: argparse.Namespace) -> int:
    log   = ReconLogger(verbose=args.verbose)
    start = time.monotonic()

    # ── Banner ──────────────────────────────────────────────────
    log.banner(BANNER)
    console.print(
        Panel(
            Text.from_markup(
                f"[bold cyan]Target[/bold cyan]       : [bold white]{args.domain}[/bold white]\n"
                f"[bold cyan]Output Dir[/bold cyan]   : [bold white]{args.output}[/bold white]\n"
                f"[bold cyan]Passive Only[/bold cyan] : [bold white]{args.passive_only}[/bold white]\n"
                f"[bold cyan]Timeout[/bold cyan]      : [bold white]{args.timeout}s[/bold white]\n"
                f"[bold cyan]Concurrency[/bold cyan]  : [bold white]{args.concurrency}[/bold white]\n"
                f"[bold cyan]Schemes[/bold cyan]      : [bold white]{', '.join(args.schemes)}[/bold white]"
            ),
            title       = "⚙  Konfigurasi Scan",
            border_style= "cyan",
        )
    )

    # ── Load wordlist ────────────────────────────────────────────
    wordlist: Optional[List[str]] = None
    if args.wordlist:
        try:
            wordlist = _load_wordlist(args.wordlist)
            log.success(f"Wordlist dimuat: {len(wordlist)} kata dari {args.wordlist}")
        except FileNotFoundError as e:
            log.error(str(e))
            return 1

    # ══════════════════════════════════════════════════════════════
    #  FASE 1: Subdomain Enumeration
    # ══════════════════════════════════════════════════════════════
    enumerator = SubdomainEnumerator(
        domain       = args.domain,
        wordlist     = wordlist,
        concurrency  = args.concurrency,
        passive_only = args.passive_only,
        verbose      = args.verbose,
    )
    subdomains = await enumerator.run()

    if not subdomains:
        log.warning("Tidak ada subdomain yang ditemukan. Keluar.")
        return 0

    resolved_count = sum(1 for s in subdomains if s.get("resolved"))
    if resolved_count == 0:
        log.warning("Tidak ada subdomain yang berhasil diresolve. HTTP probe dilewati.")
        # Tetap buat laporan
        reporter = ReportGenerator(
            domain        = args.domain,
            subdomains    = subdomains,
            probe_results = [],
            output_dir    = args.output,
            verbose       = args.verbose,
        )
        files = reporter.generate()
        log.success(f"Laporan: {files['json']}")
        return 0

    # ══════════════════════════════════════════════════════════════
    #  FASE 2: HTTP Probing
    # ══════════════════════════════════════════════════════════════
    prober = HttpProber(
        subdomains  = subdomains,
        timeout     = args.timeout,
        concurrency = args.concurrency,
        retries     = args.retries,
        schemes     = args.schemes,
        verbose     = args.verbose,
    )
    probe_results = await prober.run()

    # ══════════════════════════════════════════════════════════════
    #  FASE 3: Generate Report
    # ══════════════════════════════════════════════════════════════
    reporter = ReportGenerator(
        domain        = args.domain,
        subdomains    = subdomains,
        probe_results = probe_results,
        output_dir    = args.output,
        verbose       = args.verbose,
    )
    files = reporter.generate()

    # ── Footer ──────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    log.section("SELESAI")
    console.print(
        Panel(
            Text.from_markup(
                f"[bold green]✓ Scan selesai dalam {elapsed:.1f} detik[/bold green]\n\n"
                f"[bold cyan]Laporan JSON[/bold cyan] : [white]{files['json']}[/white]\n"
                f"[bold cyan]Ringkasan    [/bold cyan]: [white]{files['txt']}[/white]"
            ),
            title       = "📁 File Output",
            border_style= "green",
        )
    )

    return 0


# ─────────────────────────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────────────────────────
def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    # Validasi domain sederhana
    domain = args.domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        # Ekstrak hostname jika user memasukkan URL lengkap
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc or domain
    args.domain = domain

    try:
        exit_code = asyncio.run(_run_pipeline(args))
        sys.exit(exit_code)
    except KeyboardInterrupt:
        log = ReconLogger()
        log.warning("\nScan dibatalkan oleh pengguna (Ctrl+C).")
        sys.exit(130)
    except Exception as exc:
        log = ReconLogger()
        log.error(f"Error tidak terduga: {exc}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
