"""
Report renderer for SecretGuard-AI.

Produces three output formats:

1. **Terminal** — colorized Rich table with file, line, variable, masked value,
   entropy, risk, and reason columns.
2. **JSON** — machine-readable export for CI integration.
3. **HTML** — standalone report page (stretch goal).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from secretguard.config import ScanConfig
from secretguard.scanner import Finding


# ── Terminal report (Rich) ──────────────────────────────────────────────────


def render_terminal(
    findings: list[Finding],
    config: Optional[ScanConfig] = None,
) -> None:
    """Print a colorized terminal report using Rich.

    Groups findings by risk level (HIGH first), truncates after
    ``config.max_findings``, and prints remediation guidance for
    HIGH-risk items.
    """
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box

    config = config or ScanConfig()
    console = Console()

    if not findings:
        console.print(
            Panel(
                "[bold green]✅ No secrets detected![/bold green]\n"
                "Your code looks clean. Great job!",
                title="SecretGuard-AI",
                border_style="green",
                expand=False,
            )
        )
        return

    # Sort: HIGH → MEDIUM → LOW
    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings_sorted = sorted(findings, key=lambda f: risk_order.get(f.risk, 3))

    high_count = sum(1 for f in findings if f.risk == "HIGH")
    med_count = sum(1 for f in findings if f.risk == "MEDIUM")
    low_count = sum(1 for f in findings if f.risk == "LOW")

    # Header
    header_style = "bold red" if high_count else ("bold yellow" if med_count else "bold green")
    console.print()
    console.print(
        Panel(
            f"[bold]SecretGuard-AI Scan Report[/bold]\n"
            f"[red]HIGH: {high_count}[/red]  "
            f"[yellow]MEDIUM: {med_count}[/yellow]  "
            f"[green]LOW: {low_count}[/green]  "
            f"[dim]Total: {len(findings)}[/dim]",
            border_style=header_style,
            expand=False,
        )
    )

    # Findings table
    table = Table(
        box=box.ROUNDED,
        show_lines=True,
        title="Findings",
        title_style="bold",
    )
    table.add_column("Risk", style="bold", width=8, justify="center")
    table.add_column("File", style="cyan", max_width=40)
    table.add_column("Line", style="dim", width=5, justify="right")
    table.add_column("Variable", style="magenta", max_width=25)
    table.add_column("Value (masked)", max_width=35)
    table.add_column("Entropy", width=8, justify="right")
    table.add_column("Reason", max_width=50)

    displayed = findings_sorted[: config.max_findings]
    for f in displayed:
        risk_style = {
            "HIGH": "[bold red]🔴 HIGH[/bold red]",
            "MEDIUM": "[bold yellow]🟡 MED[/bold yellow]",
            "LOW": "[green]🟢 LOW[/green]",
        }.get(f.risk, f.risk)

        # Shorten file path for readability
        short_file = _shorten_path(f.file)

        table.add_row(
            risk_style,
            short_file,
            str(f.line_number),
            f.variable,
            f.masked_value or f.raw_value[:20] + "…",
            f"{f.entropy:.2f}",
            f.reason,
        )

    console.print(table)

    remaining = len(findings) - len(displayed)
    if remaining > 0:
        console.print(f"  [dim]… and {remaining} more finding(s) not shown.[/dim]")

    # Remediation guidance for HIGH findings
    if high_count > 0:
        console.print()
        console.print(
            Panel(
                "[bold red]⛔ Commit blocked![/bold red]\n\n"
                "[bold]Remediation steps:[/bold]\n"
                "  1. Move secrets to a [cyan].env[/cyan] file or a secrets manager.\n"
                "  2. Reference them via environment variables in your code.\n"
                "  3. Ensure [cyan].env[/cyan] is listed in [cyan].gitignore[/cyan].\n"
                "  4. Run [bold]secretguard scan .[/bold] again to verify.\n\n"
                "[dim]Tip: Use [bold]--json report.json[/bold] for CI-friendly output.[/dim]",
                title="🔒 Remediation Required",
                border_style="red",
                expand=False,
            )
        )
    else:
        console.print()
        console.print(
            "[green]✅ No HIGH-risk findings. Commit may proceed.[/green]"
        )


# ── JSON export ─────────────────────────────────────────────────────────────


def export_json(findings: list[Finding], output_path: Path) -> None:
    """Write findings to a JSON file.

    Args:
        findings:    List of scored findings.
        output_path: Destination file path.
    """
    data = {
        "tool": "secretguard-ai",
        "version": "0.1.0",
        "total_findings": len(findings),
        "high": sum(1 for f in findings if f.risk == "HIGH"),
        "medium": sum(1 for f in findings if f.risk == "MEDIUM"),
        "low": sum(1 for f in findings if f.risk == "LOW"),
        "findings": [
            {
                "file": f.file,
                "line": f.line_number,
                "variable": f.variable,
                "masked_value": f.masked_value or f.raw_value[:6] + "***",
                "entropy": round(f.entropy, 3),
                "risk": f.risk,
                "is_placeholder": f.is_placeholder,
                "placeholder_swap": f.placeholder_swap,
                "reason": f.reason,
            }
            for f in findings
        ],
    }
    output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ── HTML export (stretch) ──────────────────────────────────────────────────


def export_html(findings: list[Finding], output_path: Path) -> None:
    """Write findings to a standalone HTML report.

    Generates a self-contained HTML page with embedded CSS — no external
    dependencies.  Uses a dark theme for developer comfort.
    """
    high = sum(1 for f in findings if f.risk == "HIGH")
    med = sum(1 for f in findings if f.risk == "MEDIUM")
    low = sum(1 for f in findings if f.risk == "LOW")

    rows = ""
    for f in findings:
        risk_class = f.risk.lower()
        rows += f"""
        <tr class="{risk_class}">
            <td><span class="badge {risk_class}">{f.risk}</span></td>
            <td>{_html_escape(f.file)}</td>
            <td>{f.line_number}</td>
            <td><code>{_html_escape(f.variable)}</code></td>
            <td><code>{_html_escape(f.masked_value or f.raw_value[:6] + '***')}</code></td>
            <td>{f.entropy:.2f}</td>
            <td>{_html_escape(f.reason)}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecretGuard-AI Report</title>
<style>
    :root {{
        --bg: #0d1117; --surface: #161b22; --border: #30363d;
        --text: #c9d1d9; --muted: #8b949e;
        --red: #f85149; --yellow: #d29922; --green: #3fb950;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
        font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        background: var(--bg); color: var(--text); padding: 2rem;
    }}
    .header {{ text-align: center; margin-bottom: 2rem; }}
    .header h1 {{ font-size: 1.8rem; margin-bottom: .5rem; }}
    .stats {{ display: flex; gap: 1rem; justify-content: center; margin: 1rem 0; }}
    .stat {{ padding: .5rem 1.2rem; border-radius: 8px; background: var(--surface);
             border: 1px solid var(--border); font-weight: 600; }}
    .stat.high {{ color: var(--red); border-color: var(--red); }}
    .stat.medium {{ color: var(--yellow); border-color: var(--yellow); }}
    .stat.low {{ color: var(--green); border-color: var(--green); }}
    table {{ width: 100%; border-collapse: collapse; background: var(--surface);
             border-radius: 8px; overflow: hidden; }}
    th {{ background: #21262d; text-align: left; padding: .75rem 1rem;
          font-size: .85rem; text-transform: uppercase; color: var(--muted); }}
    td {{ padding: .6rem 1rem; border-top: 1px solid var(--border); font-size: .9rem; }}
    code {{ background: #1c2128; padding: 2px 6px; border-radius: 4px; font-size: .85rem; }}
    .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px;
              font-size: .75rem; font-weight: 700; text-transform: uppercase; }}
    .badge.high {{ background: rgba(248,81,73,.15); color: var(--red); }}
    .badge.medium {{ background: rgba(210,153,34,.15); color: var(--yellow); }}
    .badge.low {{ background: rgba(63,185,80,.15); color: var(--green); }}
    tr.high td {{ background: rgba(248,81,73,.04); }}
</style>
</head>
<body>
<div class="header">
    <h1>🔒 SecretGuard-AI Report</h1>
    <div class="stats">
        <div class="stat high">HIGH: {high}</div>
        <div class="stat medium">MEDIUM: {med}</div>
        <div class="stat low">LOW: {low}</div>
    </div>
</div>
<table>
<thead>
    <tr><th>Risk</th><th>File</th><th>Line</th><th>Variable</th>
        <th>Value</th><th>Entropy</th><th>Reason</th></tr>
</thead>
<tbody>{rows}
</tbody>
</table>
</body>
</html>"""

    output_path.write_text(html, encoding="utf-8")


# ── Helpers ─────────────────────────────────────────────────────────────────


def _shorten_path(filepath: str, max_parts: int = 3) -> str:
    """Shorten an absolute path to at most *max_parts* trailing components."""
    parts = Path(filepath).parts
    if len(parts) <= max_parts:
        return filepath
    return "…/" + "/".join(parts[-max_parts:])


def _html_escape(text: str) -> str:
    """Minimal HTML escaping for report content."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
