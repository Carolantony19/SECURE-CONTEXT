"""
CLI entry point for SecretGuard-AI.

Provides two main commands:

- ``secretguard scan <path>``  — Standalone full-repo audit.
- ``secretguard hook``         — Pre-commit hook mode (scans staged files).

Built with Click for clean argument parsing and help generation.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click

from secretguard import __version__
from secretguard.config import ScanConfig
from secretguard.diff_analyzer import enrich_with_diff, get_staged_files
from secretguard.report import export_html, export_json, render_terminal
from secretguard.risk_scorer import score_findings
from secretguard.scanner import Finding, scan_directory, scan_file


def _run_pipeline(
    files: list[Path],
    repo_root: Path,
    config: ScanConfig,
    *,
    use_diff: bool = False,
) -> list[Finding]:
    """Execute the full detection pipeline on a list of files.

    Pipeline stages:
        1. scanner.scan_file    →  raw findings (regex matches)
        2. risk_scorer.score    →  entropy + placeholder + composite score
        3. diff_analyzer.enrich →  placeholder-swap enrichment (optional)
        4. risk_scorer.score    →  re-score after swap data (updates labels)

    Returns:
        List of fully-scored findings.
    """
    all_findings: list[Finding] = []

    for filepath in files:
        findings = scan_file(filepath, config)
        all_findings.extend(findings)

    # First pass: score with entropy + placeholder info.
    score_findings(all_findings, config)

    # Diff enrichment (only when inside a git repo with history).
    if use_diff:
        enrich_with_diff(all_findings, repo_root, config)
        # Re-score after diff data may have set placeholder_swap flags.
        score_findings(all_findings, config)

    return all_findings


# ── CLI group ───────────────────────────────────────────────────────────────


@click.group()
@click.version_option(version=__version__, prog_name="secretguard")
def main() -> None:
    """🔒 SecretGuard-AI — Detect AI-introduced hardcoded secrets."""


# ── scan command ────────────────────────────────────────────────────────────


@main.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "--threshold",
    "-t",
    type=float,
    default=4.5,
    show_default=True,
    help="Shannon entropy threshold (bits).",
)
@click.option(
    "--json",
    "json_path",
    type=click.Path(),
    default=None,
    help="Export findings to a JSON file.",
)
@click.option(
    "--html",
    "html_path",
    type=click.Path(),
    default=None,
    help="Export findings to an HTML report.",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Show LOW-risk findings in output.",
)
@click.option(
    "--no-block",
    is_flag=True,
    default=False,
    help="Don't exit with non-zero code on HIGH findings.",
)
def scan(
    path: str,
    threshold: float,
    json_path: Optional[str],
    html_path: Optional[str],
    verbose: bool,
    no_block: bool,
) -> None:
    """Scan a file or directory for hardcoded secrets.

    Examples:

        secretguard scan .
        secretguard scan src/ --threshold 5.0 --json report.json
        secretguard scan config.env --html report.html
    """
    target = Path(path).resolve()
    config = ScanConfig(
        entropy_threshold=threshold,
        verbose=verbose,
        block_on_high=not no_block,
    )

    if target.is_file():
        files = [target]
    else:
        # Collect all files (scan_directory returns findings directly,
        # but we need file list for the pipeline).
        files = [
            f
            for f in target.rglob("*")
            if f.is_file() and f.suffix.lower() in config.scan_extensions
        ]

    findings = _run_pipeline(files, target, config, use_diff=True)

    # Filter for display.
    display = findings if verbose else [f for f in findings if f.risk != "LOW"]

    render_terminal(display, config)

    if json_path:
        export_json(findings, Path(json_path))
        click.echo(f"\n📄 JSON report saved to {json_path}")

    if html_path:
        export_html(findings, Path(html_path))
        click.echo(f"\n📄 HTML report saved to {html_path}")

    high_count = sum(1 for f in findings if f.risk == "HIGH")
    if high_count > 0 and config.block_on_high:
        sys.exit(1)


# ── hook command (pre-commit mode) ──────────────────────────────────────────


@main.command()
@click.option(
    "--threshold",
    "-t",
    type=float,
    default=4.5,
    show_default=True,
    help="Shannon entropy threshold (bits).",
)
def hook(threshold: float) -> None:
    """Run in pre-commit hook mode (scans staged files only).

    This command is invoked by the git pre-commit hook.  It:
    1. Identifies staged files via GitPython.
    2. Runs the full detection pipeline with diff analysis.
    3. Blocks the commit (exit 1) if any HIGH-risk finding is detected.
    """
    repo_root = Path.cwd().resolve()
    config = ScanConfig(
        entropy_threshold=threshold,
        block_on_high=True,
    )

    staged = get_staged_files(repo_root)
    if not staged:
        click.echo("SecretGuard: No staged files to scan.")
        sys.exit(0)

    # Filter to supported extensions.
    files = [f for f in staged if f.suffix.lower() in config.scan_extensions]
    if not files:
        click.echo("SecretGuard: No scannable files in staging area.")
        sys.exit(0)

    findings = _run_pipeline(files, repo_root, config, use_diff=True)
    display = [f for f in findings if f.risk != "LOW"]

    render_terminal(display, config)

    high_count = sum(1 for f in findings if f.risk == "HIGH")
    if high_count > 0:
        sys.exit(1)
    else:
        sys.exit(0)


# ── init command (setup helper) ─────────────────────────────────────────────


@main.command()
def init() -> None:
    """Initialize SecretGuard in the current repository.

    Creates a ``.gitignore`` entry for ``.env`` and installs the
    pre-commit hook configuration.
    """
    repo_root = Path.cwd().resolve()

    # Update .gitignore
    gitignore = repo_root / ".gitignore"
    entries_to_add = [".env", ".env.local", ".env.*.local"]

    if gitignore.exists():
        existing = gitignore.read_text(encoding="utf-8")
    else:
        existing = ""

    added = []
    for entry in entries_to_add:
        if entry not in existing:
            added.append(entry)

    if added:
        with gitignore.open("a", encoding="utf-8") as f:
            f.write("\n# SecretGuard-AI: prevent committing secret files\n")
            for entry in added:
                f.write(f"{entry}\n")
        click.echo(f"✅ Added {', '.join(added)} to .gitignore")
    else:
        click.echo("ℹ️  .gitignore already contains .env entries.")

    click.echo(
        "\n🔒 SecretGuard initialized!\n"
        "   Run 'secretguard scan .' to audit your repository.\n"
        "   See README.md for pre-commit hook setup."
    )


if __name__ == "__main__":
    main()
