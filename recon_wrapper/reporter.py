"""
=====================================================================
  Automated Recon Wrapper - Report Generator
  Membuat laporan JSON terstruktur + ringkasan teks
=====================================================================
"""

import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from collections import Counter

from .config import DEFAULT_OUTPUT_DIR, REPORT_FILENAME, SUMMARY_FILENAME
from .logger import ReconLogger, console
from rich.table import Table
from rich import box


# ─────────────────────────────────────────────────────────────────
#  Helper: statistik ringkasan
# ─────────────────────────────────────────────────────────────────
def _build_stats(
    domain        : str,
    subdomains    : List[dict],
    probe_results : List[dict],
) -> Dict[str, Any]:
    total_subs    = len(subdomains)
    resolved      = sum(1 for s in subdomains if s.get("resolved"))
    unresolved    = total_subs - resolved

    live_hosts    = [r for r in probe_results if r.get("live")]
    dead_hosts    = [r for r in probe_results if not r.get("live")]

    # Distribusi status code
    status_counts: Counter = Counter()
    server_counts: Counter = Counter()
    risk_counts  : Counter = Counter()

    for r in live_hosts:
        for probe in r.get("probes", []):
            status_counts[probe["status_code"]] += 1
            if probe.get("server"):
                server_counts[probe["server"]] += 1
            risk_counts[probe.get("risk_tag", "other")] += 1

    return {
        "total_subdomains"    : total_subs,
        "resolved_subdomains" : resolved,
        "unresolved_subdomains": unresolved,
        "live_hosts"          : len(live_hosts),
        "dead_hosts"          : len(dead_hosts),
        "live_rate_percent"   : round(len(live_hosts) / resolved * 100, 2) if resolved else 0,
        "status_code_distribution": dict(status_counts),
        "server_distribution" : dict(server_counts.most_common(10)),
        "risk_distribution"   : dict(risk_counts),
        "interesting_hosts"   : [
            {
                "url"        : r["best_url"],
                "status"     : r["best_status"],
                "title"      : r.get("best_title", ""),
                "server"     : r.get("best_server", ""),
                "ip"         : r.get("ip"),
            }
            for r in live_hosts
            if r["best_status"] not in (404,)
        ],
    }


# ─────────────────────────────────────────────────────────────────
#  Helper: cetak tabel ringkasan ke terminal
# ─────────────────────────────────────────────────────────────────
def _print_summary_table(stats: Dict[str, Any], log: ReconLogger) -> None:
    log.section("RINGKASAN HASIL RECON")

    # Tabel utama
    table = Table(
        title       = "📊 Statistik Recon",
        box         = box.ROUNDED,
        border_style= "cyan",
        show_lines  = True,
    )
    table.add_column("Metrik", style="bold cyan", min_width=30)
    table.add_column("Nilai", style="bold white", justify="right")

    rows = [
        ("Total subdomain ditemukan",  str(stats["total_subdomains"])),
        ("Berhasil diresolve (DNS)",   str(stats["resolved_subdomains"])),
        ("Gagal resolve",              str(stats["unresolved_subdomains"])),
        ("Host aktif (HTTP/HTTPS)",    f"[bold green]{stats['live_hosts']}[/bold green]"),
        ("Host tidak aktif",           f"[dim red]{stats['dead_hosts']}[/dim red]"),
        ("Tingkat keaktifan",          f"{stats['live_rate_percent']}%"),
    ]
    for name, val in rows:
        table.add_row(name, val)
    console.print(table)

    # Tabel status code
    if stats["status_code_distribution"]:
        sc_table = Table(
            title       = "📈 Distribusi Status Code",
            box         = box.SIMPLE_HEAVY,
            border_style= "magenta",
        )
        sc_table.add_column("Status Code", style="bold yellow")
        sc_table.add_column("Jumlah",      justify="right")
        for code, count in sorted(stats["status_code_distribution"].items()):
            sc_table.add_row(str(code), str(count))
        console.print(sc_table)

    # Tabel live hosts menarik
    interesting = stats.get("interesting_hosts", [])
    if interesting:
        ih_table = Table(
            title       = "🔍 Host Aktif Menarik",
            box         = box.ROUNDED,
            border_style= "green",
            show_lines  = True,
        )
        ih_table.add_column("URL",         style="bold green", min_width=35)
        ih_table.add_column("Status",      justify="center")
        ih_table.add_column("Title",       style="dim white", max_width=40)
        ih_table.add_column("Server",      style="bold yellow")
        ih_table.add_column("IP",          style="cyan")

        for h in interesting[:30]:  # max 30 baris di terminal
            ih_table.add_row(
                h["url"][:60],
                str(h["status"]),
                h.get("title", "")[:40],
                h.get("server", ""),
                h.get("ip", ""),
            )
        console.print(ih_table)


# ─────────────────────────────────────────────────────────────────
#  PUBLIC: ReportGenerator
# ─────────────────────────────────────────────────────────────────
class ReportGenerator:
    """
    Buat laporan JSON + ringkasan teks dari hasil recon.

    Parameters
    ----------
    domain       : target domain
    subdomains   : output dari SubdomainEnumerator
    probe_results: output dari HttpProber
    output_dir   : direktori output (default: ./recon_results)
    verbose      : log debug
    """

    def __init__(
        self,
        domain        : str,
        subdomains    : List[dict],
        probe_results : List[dict],
        output_dir    : str = DEFAULT_OUTPUT_DIR,
        verbose       : bool = False,
    ):
        self.domain        = domain
        self.subdomains    = subdomains
        self.probe_results = probe_results
        self.output_dir    = output_dir
        self.log           = ReconLogger(verbose=verbose)
        self.timestamp     = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    def generate(self) -> Dict[str, str]:
        """
        Hasilkan laporan JSON + ringkasan teks.
        Return dict dengan path file yang dibuat.
        """
        self.log.section("FASE 3 — Pembuatan Laporan")

        os.makedirs(self.output_dir, exist_ok=True)

        stats = _build_stats(self.domain, self.subdomains, self.probe_results)

        # ── Susun objek laporan lengkap ──────────────────────────
        report = {
            "meta": {
                "tool"          : "Automated Recon Wrapper",
                "version"       : "1.0.0",
                "target_domain" : self.domain,
                "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                "output_dir"    : os.path.abspath(self.output_dir),
            },
            "statistics": stats,
            "subdomains": self.subdomains,
            "http_probes": self.probe_results,
        }

        # ── Tulis JSON ───────────────────────────────────────────
        json_filename = REPORT_FILENAME.replace(
            "{domain}", self.domain.replace(".", "_")
        ).replace("{timestamp}", self.timestamp)
        json_path = os.path.join(self.output_dir, json_filename)

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        self.log.success(f"Laporan JSON disimpan → {json_path}")

        # ── Tulis ringkasan TXT ──────────────────────────────────
        txt_filename = SUMMARY_FILENAME.replace(
            "{domain}", self.domain.replace(".", "_")
        ).replace("{timestamp}", self.timestamp)
        txt_path = os.path.join(self.output_dir, txt_filename)
        self._write_text_summary(txt_path, stats)
        self.log.success(f"Ringkasan teks disimpan → {txt_path}")

        # ── Cetak tabel ke terminal ──────────────────────────────
        _print_summary_table(stats, self.log)

        return {"json": json_path, "txt": txt_path}

    # ──────────────────────────────────────────────────────────────
    def _write_text_summary(self, path: str, stats: Dict[str, Any]) -> None:
        """Tulis ringkasan teks yang mudah dibaca manusia."""
        sep = "=" * 65
        lines = [
            sep,
            " AUTOMATED RECON WRAPPER — RINGKASAN HASIL",
            sep,
            f" Target       : {self.domain}",
            f" Scan Time    : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            sep,
            "",
            "[ STATISTIK ]",
            f"  Total subdomain ditemukan  : {stats['total_subdomains']}",
            f"  Berhasil resolve (DNS)      : {stats['resolved_subdomains']}",
            f"  Gagal resolve               : {stats['unresolved_subdomains']}",
            f"  Host aktif (HTTP/HTTPS)     : {stats['live_hosts']}",
            f"  Host tidak aktif            : {stats['dead_hosts']}",
            f"  Tingkat keaktifan           : {stats['live_rate_percent']}%",
            "",
            "[ DISTRIBUSI STATUS CODE ]",
        ]
        for code, count in sorted(stats["status_code_distribution"].items()):
            lines.append(f"  {code}  →  {count}x")

        lines += [
            "",
            "[ SERVER TECHNOLOGIES ]",
        ]
        for server, count in stats["server_distribution"].items():
            lines.append(f"  {server}  →  {count}x")

        lines += [
            "",
            "[ HOST AKTIF MENARIK ]",
        ]
        for h in stats.get("interesting_hosts", []):
            lines.append(
                f"  [{h['status']}] {h['url']}"
                + (f"  | {h['title'][:50]}" if h.get("title") else "")
                + (f"  | {h['server']}" if h.get("server") else "")
            )

        lines += ["", sep, "  Laporan lengkap tersedia dalam file JSON.", sep, ""]

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
