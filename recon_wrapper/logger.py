"""
=====================================================================
  Automated Recon Wrapper - Logger Utility
  Rich-based pretty logging dengan warna & ikon
=====================================================================
"""

from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
from rich.text import Text
import sys

# ─── Custom Theme ─────────────────────────────────────────────────
_theme = Theme({
    "info"    : "bold cyan",
    "success" : "bold green",
    "warning" : "bold yellow",
    "error"   : "bold red",
    "highlight": "bold magenta",
    "muted"   : "dim white",
    "subdomain": "bold blue",
    "live"    : "bold green",
    "dead"    : "dim red",
})

import io

# Bungkus stdout/stderr dengan UTF-8 agar karakter non-ASCII aman di Windows
_stdout_utf8 = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
_stderr_utf8 = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

console        = Console(theme=_theme, highlight=False, force_terminal=True, file=_stdout_utf8)
console_stderr = Console(theme=_theme, highlight=False, force_terminal=True, file=_stderr_utf8)


class ReconLogger:
    """Logger terpusat dengan level dan ikon."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def info(self, msg: str) -> None:
        console.print(f"[info]  [*][/info] {msg}")

    def success(self, msg: str) -> None:
        console.print(f"[success]  [+][/success] {msg}")

    def warning(self, msg: str) -> None:
        console.print(f"[warning]  [!][/warning] {msg}")

    def error(self, msg: str) -> None:
        console_stderr.print(f"[error]  [-][/error] {msg}")

    def debug(self, msg: str) -> None:
        if self.verbose:
            console.print(f"[muted]  [~] {msg}[/muted]")

    def found(self, subdomain: str, ip: str = "") -> None:
        ip_tag = f"[muted]({ip})[/muted]" if ip else ""
        console.print(f"[subdomain]  [>][/subdomain] {subdomain} {ip_tag}")

    def live(self, url: str, status: int, title: str = "", server: str = "") -> None:
        extras = []
        if title:
            extras.append(f"[muted]{title[:50]}[/muted]")
        if server:
            extras.append(f"[highlight]{server}[/highlight]")
        extra_str = "  ".join(extras)
        console.print(f"[live]  [LIVE][/live] [bold]{url}[/bold]  [{status}]  {extra_str}")

    def dead(self, url: str, reason: str = "") -> None:
        console.print(f"[dead]  [DEAD][/dead] {url}  {reason}")

    def section(self, title: str) -> None:
        console.print()
        console.rule(f"[bold cyan]{title}[/bold cyan]")
        console.print()

    def panel(self, content: str, title: str = "") -> None:
        console.print(Panel(content, title=title, border_style="cyan"))

    def banner(self, text: str) -> None:
        console.print(text, style="bold cyan")
