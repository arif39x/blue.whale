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
    "critical": "\033[31;1m",  # Red Bold
    "high": "\033[33;1m",      # Yellow Bold
    "medium": "\033[33m",      # Yellow
    "low": "\033[32m",         # Green
    "info": "\033[32m",        # Green
    "reset": "\033[0m",
    "matrix": "\033[32m",      # Matrix Green
}


def _c(sev: str, text: str) -> str:
    return f"{_COLOURS.get(sev.lower(), '')}{text}{_COLOURS['reset']}"


def _print_finding(f) -> None:
    sev = f.severity.value
    click.echo(f"  {_c(sev, f'[{sev.upper():8s}]')}  {f.name:<40s}  {f.url}")


def _print_node(msg: dict) -> None:
    url = msg.get("url", "")
    params = msg.get("params", [])
    score = msg.get("score", 0.0)
    depth = msg.get("depth", 0)
    param_str = f"  params=[{', '.join(params)}]" if params else ""
    click.echo(f"  \033[32m[+] NODE_DISCOVERED (d={depth} s={score:.1f})\033[0m {url}{param_str}")


def _print_status(msg: dict) -> None:
    phase = msg.get("phase", "")
    progress = msg.get("progress", 0)
    detail = msg.get("detail", "")
    
    # Trim detail if too long for terminal
    if len(detail) > 50:
        detail = detail[:47] + "..."
        
    click.echo(
        f"  \033[32;1m[EXECUTING_{phase.upper()}]\033[0m {progress}% | {detail:<50}", nl=False
    )
    click.echo("\r", nl=False)


def _print_summary(parser: ResultParser) -> None:
    stats = parser.stats
    click.echo("\n" + "\033[32m=" * 60)
    click.echo(" [ SYSTEM_SCAN_RECAP ]")
    click.echo("=" * 60 + "\033[0m")
    any_found = False
    for sev in ("critical", "high", "medium", "low", "info"):
        count = stats.get(sev, 0)
        if count:
            click.echo(f"  {_c(sev, f'{sev.upper():12s}')} {count}")
            any_found = True
    if not any_found:
        click.echo("  NO_VULNS_DETECTED.")
    click.echo("\033[32m" + "=" * 60 + "\033[0m")


@click.group()
@click.version_option("2.0.0", prog_name="whale")
def cli() -> None:
    pass


@cli.command("scan")
@click.option("--target", "-t", required=True, help="Target URL to scan.")
@click.option(
    "--header",
    "-H",
    default=None,
    help="Custom HTTP header (e.g., Cookie: session=abc)",
)
@click.option(
    "--rps", default=None, type=int, help="Requests per second (overrides config)."
)
@click.option("--timeout", default=None, type=int, help="Hard timeout in seconds.")
@click.option(
    "--severity",
    default=None,
    help="Comma-separated severity filter, e.g. critical,high",
)
@click.option("--output", "-o", default=None, help="Output directory for reports.")
@click.option(
    "--format",
    "fmt",
    default="json",
    type=click.Choice(["json", "csv", "pdf"]),
    show_default=True,
)
@click.option(
    "--profile",
    default=None,
    help="Scan profile from settings.yaml (e.g. full, fast, stealth)",
)
@click.option(
    "--show-nodes",
    is_flag=True,
    default=False,
    help="Print discovered endpoint nodes live.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Print plan without running the scan.",
)
@click.option("--verbose", "-v", is_flag=True, default=False)
def cmd_scan(
    target: str,
    header: str | None,
    rps: int | None,
    timeout: int | None,
    severity: str | None,
    output: str | None,
    fmt: str,
    profile: str | None,
    show_nodes: bool,
    dry_run: bool,
    verbose: bool,
) -> None:
    # Run a full recon + vulnerability scan against TARGET.
    _setup_logging(verbose)
    cfg = yaml.safe_load(SETTINGS_FILE.read_text())

    # Load profile
    prof_cfg: dict = {}
    if profile:
        if "profiles" in cfg and profile in cfg["profiles"]:
            prof_cfg = cfg["profiles"][profile]
            click.echo(f"  Profile: {profile}")
        else:
            click.echo(
                f"  [ERROR] Profile '{profile}' not found in {SETTINGS_FILE}", err=True
            )
            sys.exit(1)

    # Explicit flag > profile > config default
    final_rps = rps or prof_cfg.get("rps") or cfg["scan"]["default_rps"]

    if severity:
        sev_list = [s.strip() for s in severity.split(",")]
    elif "severity_filter" in prof_cfg:
        sev_list = prof_cfg["severity_filter"]
    else:
        sev_list = cfg["scan"]["severity_filter"]

    out_dir = Path(output) if output else ensure_dir(REPORTS_DIR)

    click.echo(f"\n  Blue Whale -> {target}")
    if dry_run:
        click.echo("  [DRY RUN] Engine will not be spawned.\n")

    executor = ScanExecutor(
        target=target,
        header=header,
        rps=final_rps,
        timeout=timeout,
        severity=sev_list,
        dry_run=dry_run,
    )
    parser = ResultParser(severity_filter=sev_list)

    node_count = 0

    async def _run() -> None:
        nonlocal node_count

        is_running = True

        async def spinner_task() -> None:
            chars = ["|", "/", "-", "\\"]
            idx = 0
            while is_running:
                sys.stdout.write(f"\r  \033[32m{chars[idx]}\033[0m RUNNING_SCAN... ")
                sys.stdout.flush()
                idx = (idx + 1) % len(chars)
                await asyncio.sleep(0.1)
            # clear line
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()

        spin_task = None
        if not show_nodes and not verbose:
            spin_task = asyncio.create_task(spinner_task())

        try:
            async for msg in executor.run():
                msg_type = msg.get("type", "")

                if msg_type == "node":
                    node_count += 1
                    if show_nodes:
                        _print_node(msg)

                elif msg_type == "oast_hit":
                    if spin_task:
                        sys.stdout.write("\r\033[K")
                    protocol = msg.get("protocol", "UNKNOWN")
                    identifier = msg.get("identifier", "unknown")
                    remote_addr = msg.get("remote_addr", "unknown")
                    click.echo(f"  \033[91m[OAST HIT]\033[0m {protocol} interaction from {remote_addr} (ID: {identifier})")
                    synthetic = {
                        "template-id": f"oast-{protocol.lower()}",
                        "info": {
                            "name": f"Out-of-Band {protocol} Interaction",
                            "severity": "high",
                        },
                        "host": target,
                        "matched-at": f"OAST ID: {identifier}",
                    }
                    finding = parser.ingest(json.dumps(synthetic))
                    if finding:
                        _print_finding(finding)

                elif msg_type == "fuzz_result":
                    # Try to build a finding from this result for the parser
                    # fuzz_result is a low-level event; parser ingests it if it maps to a vuln
                    status = msg.get("status", 0)
                    reflect = msg.get("reflect", False)
                    timing = msg.get("timing_hit", False)
                    # Synthesise a minimal nuclei-compatible finding for reflection/timing
                    if reflect:
                        if spin_task:
                            sys.stdout.write("\r\033[K")
                        synthetic = {
                            "template-id": "xss-reflection",
                            "info": {
                                "name": "XSS Reflection Detected",
                                "severity": "medium",
                            },
                            "host": target,
                            "matched-at": msg.get("url", target),
                            "status-code": status,
                        }
                        finding = parser.ingest(json.dumps(synthetic))
                        if finding:
                            _print_finding(finding)
                    if timing:
                        if spin_task:
                            sys.stdout.write("\r\033[K")
                        synthetic = {
                            "template-id": "time-based-sqli",
                            "info": {
                                "name": "Time-Based Injection (Timing Oracle)",
                                "severity": "high",
                            },
                            "host": target,
                            "matched-at": msg.get("url", target),
                            "status-code": status,
                        }
                        finding = parser.ingest(json.dumps(synthetic))
                        if finding:
                            _print_finding(finding)

                elif msg_type == "status":
                    if verbose:
                        _print_status(msg)

                elif msg_type == "scan_done":
                    total = msg.get("total_nodes", node_count)
                    click.echo(f"\n  Crawl complete - {total} endpoints discovered.")

                elif msg_type == "error":
                    if spin_task:
                        sys.stdout.write("\r\033[K")
                    click.echo(
                        f"\n  \033[91m[ERROR]\033[0m {msg.get('message', '')}", err=True
                    )

                elif msg_type == "dry_run":
                    click.echo(
                        f"  DRY RUN: would scan {msg.get('target')} (job {msg.get('job_id')})"
                    )

        finally:
            is_running = False
            if spin_task:
                await spin_task

    asyncio.run(_run())

    _print_summary(parser)

    if not dry_run:
        reporter = Reporter(target=target, job_id=executor.job_id)
        reporter.load_from_parser(parser)

        if fmt == "json":
            path = parser.export_jsonl(out_dir / f"whale_{executor.job_id}.jsonl")
            click.echo(f"\n  JSONL export -> {path}")
        elif fmt == "csv":
            path = parser.export_csv(out_dir / f"whale_{executor.job_id}.csv")
            click.echo(f"\n  CSV export -> {path}")
        elif fmt == "pdf":
            path = reporter.export_pdf(out_dir)
            if path:
                click.echo(f"\n  PDF report -> {path}")
            else:
                click.echo("\n  PDF generation failed (install weasyprint).")


@cli.command("report")
@click.argument("results_file", type=click.Path(exists=True, path_type=Path))
@click.option("--target", default="unknown", help="Target URL label for the report.")
@click.option("--output", "-o", default=None, help="Output directory for the report.")
@click.option(
    "--format",
    "fmt",
    default="pdf",
    type=click.Choice(["pdf"]),
    show_default=True,
)
@click.option(
    "--severity", default=None, help="Filter severities from the JSONL input."
)
def cmd_report(
    results_file: Path,
    target: str,
    output: str | None,
    fmt: str,
    severity: str | None,
) -> None:
    # Generate a PDF report from a JSONL RESULTS_FILE.
    sev_list = [s.strip() for s in severity.split(",")] if severity else None
    out_dir = Path(output) if output else ensure_dir(REPORTS_DIR)

    click.echo(f"  Generating {fmt.upper()} report from {results_file}...")
    parser = ResultParser.from_file(results_file, severity_filter=sev_list)
    reporter = Reporter(target=target, job_id=results_file.stem)
    reporter.load_from_parser(parser)

    path = reporter.export_pdf(out_dir)
    if path:
        click.echo(f"  Report saved -> {path}")
    else:
        click.echo("  Report generation failed.", err=True)
        sys.exit(1)


@cli.command("bootstrap")
@click.option(
    "--force", is_flag=True, default=False, help="Rebuild engine even if binary exists."
)
def cmd_bootstrap(force: bool) -> None:
    # Build the Go engine and set up the Python environment.
    args = ["bash", str(BOOTSTRAP_SCRIPT)]
    if force:
        args.append("--force")
    result = subprocess.run(args, check=False)
    sys.exit(result.returncode)


@cli.command("paths")
def cmd_paths() -> None:
    # Print all resolved filesystem paths and their existence status.
    click.echo("\n  Blue Whale Path Resolution\n")
    for name, p in all_paths().items():
        status = (
            click.style("[OK]", fg="green")
            if p.exists()
            else click.style("[XX]", fg="red")
        )
        click.echo(f"  {status}  {name:25s}  {p}")
    click.echo()
