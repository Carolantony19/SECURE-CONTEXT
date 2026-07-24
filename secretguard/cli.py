"""
CLI entry point for SecretGuard AI.

Two main operating modes:
- ``secretguard check --staged``  — Fast pre-commit mode (scans staged files).
- ``secretguard scan [path]``     — Full directory audit.
- ``secretguard scan --history``  — Deep full-repo git history analysis.
- ``secretguard init``            — Setup helper.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click

from secretguard import __version__
from secretguard.config import ScanConfig
from secretguard.diff_analyzer import enrich_with_diff, get_staged_files
from secretguard.history_analyzer import analyze_history
from secretguard.report import export_json, export_sarif, render_terminal
from secretguard.risk_scorer import score_findings
from secretguard.scanner import Finding, scan_directory, scan_file


def _run_pipeline(
    files: list[Path],
    repo_root: Path,
    config: ScanConfig,
    *,
    use_diff: bool = False,
) -> list[Finding]:
    """Execute the full detection pipeline on a list of files."""
    all_findings: list[Finding] = []
    for filepath in files:
        all_findings.extend(scan_file(filepath, config))

    score_findings(all_findings, config, repo_root)

    if use_diff:
        enrich_with_diff(all_findings, repo_root, config)
        score_findings(all_findings, config, repo_root)

    return all_findings


def _output(findings: list[Finding], config: ScanConfig) -> None:
    """Route output to the configured format."""
    if config.output_format == "json" and config.output_file:
        export_json(findings, config.output_file)
        click.echo(f"📄 JSON report saved to {config.output_file}")
    elif config.output_format == "sarif" and config.output_file:
        export_sarif(findings, config.output_file)
        click.echo(f"📄 SARIF report saved to {config.output_file}")
    else:
        render_terminal(findings, config)


# ── CLI group ───────────────────────────────────────────────────────────────


@click.group()
@click.version_option(version=__version__, prog_name="secretguard")
def main() -> None:
    """🔒 SecretGuard AI — Detect AI-introduced hardcoded secrets."""


# ── check command (pre-commit mode) ────────────────────────────────────────


@main.command()
@click.option("--staged", is_flag=True, default=False,
              help="Scan only git-staged files (pre-commit mode).")
@click.option("--threshold", "-t", type=float, default=4.5,
              show_default=True, help="Shannon entropy threshold (bits).")
@click.option("--format", "fmt", type=click.Choice(["terminal", "json", "sarif"]),
              default="terminal", help="Output format.")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Output file path (for json/sarif).")
def check(staged: bool, threshold: float, fmt: str, output: Optional[str]) -> None:
    """Pre-commit check — scan staged files or working directory.

    Examples:
        secretguard check --staged
        secretguard check --staged --format sarif -o results.sarif
    """
    repo_root = Path.cwd().resolve()
    config = ScanConfig.load(repo_root)
    config.entropy_threshold = threshold
    config.output_format = fmt
    config.output_file = Path(output) if output else None
    config.block_on_high = True

    if staged:
        files = get_staged_files(repo_root)
        if not files:
            click.echo("SecretGuard: No staged files to scan.")
            sys.exit(0)
        files = [f for f in files if f.suffix.lower() in config.scan_extensions
                 or f.name in config.scan_filenames]
    else:
        files = [
            f for f in repo_root.rglob("*")
            if f.is_file() and (f.suffix.lower() in config.scan_extensions
                                or f.name in config.scan_filenames)
        ]

    findings = _run_pipeline(files, repo_root, config, use_diff=staged)
    display = findings if config.verbose else [
        f for f in findings if f.risk not in ("LOW", "SUPPRESSED")
    ]

    _output(display, config)

    high_count = sum(1 for f in findings if f.risk == "HIGH")
    sys.exit(1 if high_count > 0 else 0)


# ── scan command (full audit) ──────────────────────────────────────────────


@main.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--history", is_flag=True, default=False,
              help="Walk full git history for placeholder-lineage swaps.")
@click.option("--threshold", "-t", type=float, default=4.5,
              show_default=True, help="Shannon entropy threshold (bits).")
@click.option("--format", "fmt", type=click.Choice(["terminal", "json", "sarif"]),
              default="terminal", help="Output format.")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Output file path (for json/sarif).")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Show LOW-risk findings.")
@click.option("--no-block", is_flag=True, default=False,
              help="Don't exit with non-zero on HIGH findings.")
def scan(
    path: str, history: bool, threshold: float,
    fmt: str, output: Optional[str], verbose: bool, no_block: bool,
) -> None:
    """Scan a file or directory for hardcoded secrets.

    Examples:
        secretguard scan .
        secretguard scan src/ --threshold 5.0 --format json -o report.json
        secretguard scan . --history
    """
    target = Path(path).resolve()
    config = ScanConfig.load(target if target.is_dir() else target.parent)
    config.entropy_threshold = threshold
    config.output_format = fmt
    config.output_file = Path(output) if output else None
    config.verbose = verbose
    config.block_on_high = not no_block

    findings: list[Finding] = []

    if target.is_file():
        findings = _run_pipeline([target], target.parent, config, use_diff=True)
    else:
        findings = scan_directory(target, config)
        score_findings(findings, config, target)

    # History mode: also walk the full git log
    if history:
        click.echo("🔍 Analyzing full git history (this may take a moment)…")
        lineage = analyze_history(target, config)
        score_findings(lineage, config, target)
        findings.extend(lineage)

    display = findings if verbose else [
        f for f in findings if f.risk not in ("LOW", "SUPPRESSED")
    ]

    _output(display, config)

    if fmt == "json" and output:
        export_json(findings, Path(output))
    if fmt == "sarif" and output:
        export_sarif(findings, Path(output))

    high_count = sum(1 for f in findings if f.risk == "HIGH")
    if high_count > 0 and config.block_on_high:
        sys.exit(1)


# ── init command ────────────────────────────────────────────────────────────


@main.command()
def init() -> None:
    """Initialize SecretGuard in the current repository."""
    repo_root = Path.cwd().resolve()

    # .gitignore updates
    gitignore = repo_root / ".gitignore"
    entries = [".env", ".env.local", ".env.*.local"]
    existing = gitignore.read_text(encoding="utf-8") if gitignore.exists() else ""
    added = [e for e in entries if e not in existing]
    if added:
        with gitignore.open("a", encoding="utf-8") as f:
            f.write("\n# SecretGuard AI: prevent committing secret files\n")
            for entry in added:
                f.write(f"{entry}\n")
        click.echo(f"✅ Added {', '.join(added)} to .gitignore")

    # Create example .secretguardignore
    ignore_file = repo_root / ".secretguardignore"
    if not ignore_file.exists():
        ignore_file.write_text(
            "# SecretGuard AI allowlist\n"
            "# One pattern per line. Supports:\n"
            "#   - File globs: tests/fixtures/*\n"
            "#   - Variable names: EXAMPLE_KEY\n"
            "#   - SHA-256 fingerprints: sha256:<hex>\n",
            encoding="utf-8",
        )
        click.echo("✅ Created .secretguardignore")

    click.echo(
        "\n🔒 SecretGuard AI initialized!\n"
        "   Run 'secretguard scan .' to audit your repository.\n"
        "   Run 'secretguard check --staged' in your pre-commit hook."
    )


if __name__ == "__main__":
    main()
