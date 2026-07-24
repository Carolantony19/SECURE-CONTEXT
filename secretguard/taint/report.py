"""
Taint flow report renderer for SecretGuard AI.

Formats interprocedural taint traces for terminal console, JSON, and SARIF outputs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from secretguard.taint.taint_tracker import TaintFlow


def render_taint_terminal(flows: list[TaintFlow]) -> None:
    """Render colorised Rich terminal report for detected secret flows."""
    if not flows:
        return

    from rich import box
    from rich.console import Console
    from rich.panel import Panel

    console = Console()

    console.print()
    console.print(Panel(
        f"[bold red]⚠️ SECRET FLOW DETECTED ({len(flows)} flow(s))[/bold red]\n"
        "[dim]A secret credential propagates into a dangerous operation (sink).[/dim]",
        border_style="red", expand=False,
    ))

    for idx, flow in enumerate(flows, 1):
        lines: list[str] = []

        orig_rel = _rel(flow.origin_file)
        sink_rel = _rel(flow.sink_file)

        lines.append(f"[bold red]Flow #{idx}: {flow.origin_variable} ➔ {flow.sink_name}[/bold red]")
        lines.append(f"  [cyan]Origin:[/cyan]  {orig_rel}:{flow.origin_line:<4}  {flow.origin_variable} = \"{_mask(flow.raw_secret_value)}\"")

        for step in flow.steps[1:-1]:
            s_rel = _rel(step.file)
            lines.append(f"  [yellow]Flow:[/yellow]    {s_rel}:{step.line_number:<4}  {step.detail} ({step.expression})")

        lines.append(f"  [red]Sink:[/red]    {sink_rel}:{flow.sink_line:<4}  {flow.sink_name} ({flow.sink_description})")
        lines.append(f"  [bold yellow]Risk:[/bold yellow]    HIGH — secret reaches {flow.sink_category.lower()} operation")

        console.print(Panel(
            "\n".join(lines),
            box=box.ROUNDED,
            border_style="red",
            expand=False,
        ))


def _rel(path: Path) -> str:
    parts = path.parts
    return "/".join(parts[-2:]) if len(parts) >= 2 else path.name


def _mask(val: str) -> str:
    if len(val) <= 6:
        return val
    return val[:6] + "*" * (len(val) - 6)
