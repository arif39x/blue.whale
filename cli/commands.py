from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import sys
from pathlib import Path

import click
import yaml

from core.executor import ScanExecutor
from core.parser import ResultParser
from core.paths import (
    BOOTSTRAP_SCRIPT,
    REPORTS_DIR,
    SETTINGS_FILE,
    all_paths,
    ensure_dir,
)
from core.reporter import Reporter

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )


_COLOURS = {
    "critical": "\033[91m",  # bright red
    "high":     "\033[93m",  # bright yellow
    "medium":   "\033[33m",  # yellow
    "low":      "\033[32m",  # green
    "info":     "\033[36m",  # cyan
    "reset":    "\033[0m",
}


def _colourise(sev: str, text: str) -> str:
    c = _COLOURS.get(sev.lower(), "")
    r = _COLOURS["reset"]
    return f"{c}{text}{r}"


def _print_finding(f) -> None:
    sev = f.severity.value
    click.echo(
        f"  {_colourise(sev, f'[{sev.upper():8s}]')}  "
        f"{f.name:<40s}  {f.url}"
    )


def _print_summary(parser: ResultParser) -> None:
    stats = parser.stats
    click.echo("\n" + "─" * 60)
    click.echo("  Summary")
    click.echo("─" * 60)
    for sev in ("critical", "high", "medium", "low", "info"):
        count = stats.get(sev, 0)
        if count:
            click.echo(f"  {_colourise(sev, f'{sev.upper():10s}')}  {count}")
    click.echo("─" * 60)



@click.group()
@click.version_option("1.0.0", prog_name="moriarty")
def cli() -> None:
    # Moriarty — Modular web vulnerability orchestrator.
    pass



@cli.command("scan")
@click.option("--target", "-t", required=True, help="Target URL to scan.")
@click.option("--rps", default=None, type=int, help="Requests per second (overrides config).")
@click.option("--timeout", default=None, type=int, help="Hard timeout in seconds.")
@click.option(
    "--severity",
    default=None,
    help="Comma-separated severity filter, e.g. critical,high",
)
@click.option("--output", "-o", default=None, help="Output directory for reports.")
@click.option("--format", "fmt", default="html", type=click.Choice(["html", "json", "csv", "pdf"]), show_default=True)
@click.option("--dry-run", is_flag=True, default=False, help="Print plan without running scan.")
@click.option("--verbose", "-v", is_flag=True, default=False)
def cmd_scan(
    target: str,
    rps: int | None,
    timeout: int | None,
    severity: str | None,
    output: str | None,
    fmt: str,
    dry_run: bool,
    verbose: bool,
) -> None:
    # Run a full recon + vulnerability scan against TARGET.
    _setup_logging(verbose)
    cfg = yaml.safe_load(SETTINGS_FILE.read_text())

    sev_list = [s.strip() for s in severity.split(",")] if severity else cfg["scan"]["severity_filter"]
    out_dir = Path(output) if output else ensure_dir(REPORTS_DIR)

    click.echo(f"\nMoriarty Scan → {target}")
    if dry_run:
        click.echo("  [DRY RUN] No actual scanning will be performed.\n")

    executor = ScanExecutor(
        target=target,
        rps=rps,
        timeout=timeout,
        severity=sev_list,
        dry_run=dry_run,
    )
    parser = ResultParser(severity_filter=sev_list)

    async def _run() -> None:
        async for line in executor.run():
            finding = parser.ingest(line)
            if finding:
                _print_finding(finding)

    asyncio.run(_run())

    _print_summary(parser)

    if not dry_run:
        reporter = Reporter(target=target, job_id=executor.job_id)
        reporter.load_from_parser(parser)

        if fmt == "html":
            path = reporter.export_html(out_dir)
            click.echo(f"\n    HTML report → {path}")
        elif fmt == "json":
            path = parser.export_jsonl(out_dir / f"moriarty_{executor.job_id}.jsonl")
            click.echo(f"\n    JSONL export → {path}")
        elif fmt == "csv":
            path = parser.export_csv(out_dir / f"moriarty_{executor.job_id}.csv")
            click.echo(f"\n    CSV export → {path}")
        elif fmt == "pdf":
            path = reporter.export_pdf(out_dir)
            if path:
                click.echo(f"\n    PDF report → {path}")
            else:
                click.echo(f"\n    PDF generation failed.")


@cli.command("report")
@click.argument("results_file", type=click.Path(exists=True, path_type=Path))
@click.option("--target", default="unknown", help="Target URL label for the report.")
@click.option("--output", "-o", default=None, help="Output directory for the report.")
@click.option("--format", "fmt", default="html", type=click.Choice(["html", "pdf"]), show_default=True)
@click.option("--severity", default=None, help="Filter severities from the JSONL input.")
def cmd_report(
    results_file: Path,
    target: str,
    output: str | None,
    fmt: str,
    severity: str | None,
) -> None:
    # Generate an HTML/PDF report from a JSONL RESULTS_FILE.
    sev_list = [s.strip() for s in severity.split(",")] if severity else None
    out_dir = Path(output) if output else ensure_dir(REPORTS_DIR)

    click.echo(f"Generating {fmt.upper()} report from {results_file}…")
    parser = ResultParser.from_file(results_file, severity_filter=sev_list)
    reporter = Reporter(target=target, job_id=results_file.stem)
    reporter.load_from_parser(parser)

    if fmt == "html":
        path = reporter.export_html(out_dir)
    elif fmt == "pdf":
        path = reporter.export_pdf(out_dir)
    else:
        path = None

    if path:
        click.echo(f" Report saved → {path}")
    else:
        click.echo(" Report generation failed .", err=True)
        sys.exit(1)



@cli.command("bootstrap")
@click.option("--force", is_flag=True, default=False, help="Re-download even if binaries exist.")
def cmd_bootstrap(force: bool) -> None:
    # Download and install required binaries (Nuclei, Katana, ffuf).
    args = ["bash", str(BOOTSTRAP_SCRIPT)]
    if force:
        args.append("--force")
    result = subprocess.run(args, check=False)
    sys.exit(result.returncode)



@cli.command("paths")
def cmd_paths() -> None:
    # Print all resolved filesystem paths and their existence status.

    click.echo("\n  Moriarty Path Resolution\n")
    for name, p in all_paths().items():
        status = click.style("[OK]", fg="green") if p.exists() else click.style("[XX]", fg="red")
        click.echo(f"  {status}  {name:25s}  {p}")
    click.echo()
