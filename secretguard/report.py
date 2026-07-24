"""
Report renderer for SecretGuard AI.

Produces three output formats:
1. **Terminal** — colorised Rich table with remediation guidance.
2. **JSON** — machine-readable export for CI integration.
3. **SARIF** — Static Analysis Results Interchange Format for
   GitHub Advanced Security integration.
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
    """Print a colorised terminal report using Rich."""
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    config = config or ScanConfig()
    console = Console()

    # Filter suppressed
    visible = [f for f in findings if f.risk != "SUPPRESSED"]
    if not visible:
        console.print(Panel(
            "[bold green]✅ No secrets detected![/bold green]\n"
            "Your code looks clean.",
            title="SecretGuard AI", border_style="green", expand=False,
        ))
        return

    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    visible.sort(key=lambda f: risk_order.get(f.risk, 3))

    high = sum(1 for f in visible if f.risk == "HIGH")
    med = sum(1 for f in visible if f.risk == "MEDIUM")
    low = sum(1 for f in visible if f.risk == "LOW")

    style = "bold red" if high else ("bold yellow" if med else "bold green")
    console.print()
    console.print(Panel(
        f"[bold]SecretGuard AI Scan Report[/bold]\n"
        f"[red]HIGH: {high}[/red]  "
        f"[yellow]MEDIUM: {med}[/yellow]  "
        f"[green]LOW: {low}[/green]  "
        f"[dim]Total: {len(visible)}[/dim]",
        border_style=style, expand=False,
    ))

    table = Table(box=box.ROUNDED, show_lines=True, title="Findings")
    table.add_column("Risk", width=8, justify="center")
    table.add_column("File", style="cyan", max_width=40)
    table.add_column("Line", width=5, justify="right")
    table.add_column("Variable", style="magenta", max_width=25)
    table.add_column("Value (masked)", max_width=35)
    table.add_column("Entropy", width=8, justify="right")
    table.add_column("Reason", max_width=50)

    for f in visible[:config.max_findings]:
        risk_badge = {
            "HIGH": "[bold red]🔴 HIGH[/bold red]",
            "MEDIUM": "[bold yellow]🟡 MED[/bold yellow]",
            "LOW": "[green]🟢 LOW[/green]",
        }.get(f.risk, f.risk)

        short_file = _shorten_path(f.file)
        line_str = str(f.line_number) if f.line_number else "—"
        commit = f" @{f.commit_sha}" if f.commit_sha else ""

        table.add_row(
            risk_badge, short_file + commit, line_str,
            f.variable,
            f.masked_value or f.raw_value[:20] + "…",
            f"{f.entropy:.2f}", f.reason,
        )

    console.print(table)

    remaining = len(visible) - config.max_findings
    if remaining > 0:
        console.print(f"  [dim]… and {remaining} more finding(s).[/dim]")

    if high > 0:
        console.print()
        console.print(Panel(
            "[bold red]⛔ Commit blocked![/bold red]\n\n"
            "[bold]Remediation steps:[/bold]\n"
            "  1. Move secrets to a [cyan].env[/cyan] file or secrets manager.\n"
            "  2. Reference them via environment variables.\n"
            "  3. Ensure [cyan].env[/cyan] is in [cyan].gitignore[/cyan].\n"
            "  4. Run [bold]secretguard check --staged[/bold] again.\n\n"
            "[dim]Use [bold]--format json[/bold] or [bold]--format sarif[/bold] "
            "for CI output.[/dim]",
            title="🔒 Remediation Required", border_style="red", expand=False,
        ))
    else:
        console.print("\n[green]✅ No HIGH-risk findings. Commit may proceed.[/green]")


# ── JSON export ─────────────────────────────────────────────────────────────


def export_json(findings: list[Finding], output_path: Path) -> None:
    """Write findings to a JSON file."""
    data = {
        "tool": "secretguard-ai",
        "version": "1.0.0",
        "total": len(findings),
        "high": sum(1 for f in findings if f.risk == "HIGH"),
        "medium": sum(1 for f in findings if f.risk == "MEDIUM"),
        "low": sum(1 for f in findings if f.risk == "LOW"),
        "findings": [_finding_to_dict(f) for f in findings],
    }
    output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ── SARIF export ────────────────────────────────────────────────────────────


def export_sarif(findings: list[Finding], output_path: Path) -> None:
    """Write findings in SARIF 2.1.0 format for GitHub Advanced Security.

    SARIF (Static Analysis Results Interchange Format) is the standard
    for uploading results to GitHub code scanning.
    """
    results = []
    rules_map: dict[str, dict] = {}

    for f in findings:
        rule_id = f.rule_id or f"SG{f.risk[0]}{len(rules_map):03d}"
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": f"SecretGuard: {f.risk} risk secret"},
                "defaultConfiguration": {
                    "level": {"HIGH": "error", "MEDIUM": "warning"}.get(
                        f.risk, "note"
                    )
                },
            }

        results.append({
            "ruleId": rule_id,
            "level": {"HIGH": "error", "MEDIUM": "warning"}.get(f.risk, "note"),
            "message": {"text": f.reason or f"Potential secret in {f.variable}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.file.replace("\\", "/"),
                    },
                    "region": {
                        "startLine": max(f.line_number, 1),
                    },
                },
            }],
            "properties": {
                "entropy": round(f.entropy, 3),
                "placeholder_swap": f.placeholder_swap,
                "commit_sha": f.commit_sha,
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SecretGuard AI",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/Carolantony19/SECURE-CONTEXT",
                    "rules": list(rules_map.values()),
                },
            },
            "results": results,
        }],
    }
    output_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")


# ── Helpers ─────────────────────────────────────────────────────────────────


def _finding_to_dict(f: Finding) -> dict:
    return {
        "file": f.file, "line": f.line_number, "variable": f.variable,
        "masked_value": f.masked_value or f.raw_value[:6] + "***",
        "entropy": round(f.entropy, 3), "risk": f.risk,
        "is_placeholder": f.is_placeholder,
        "placeholder_swap": f.placeholder_swap,
        "commit_sha": f.commit_sha, "reason": f.reason,
    }


def _shorten_path(filepath: str, max_parts: int = 3) -> str:
    parts = Path(filepath).parts
    if len(parts) <= max_parts:
        return filepath
    return "…/" + "/".join(parts[-max_parts:])
