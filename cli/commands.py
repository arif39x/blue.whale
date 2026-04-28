from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import sys
from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

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

console = Console()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )


_SEV_COLORS = {
    "critical": "bold red",
    "high": "bold yellow",
    "medium": "yellow",
    "low": "green",
    "info": "cyan",
}


def _print_finding(f) -> None:
    sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
    color = _SEV_COLORS.get(sev.lower(), "white")
    console.print(f"  [{color}][{sev.upper():8s}][/{color}]  {f.name:<40s}  {f.url}")


def _print_node(msg: dict) -> None:
    url = msg.get("url", "")
    params = msg.get("params", [])
    score = msg.get("score", 0.0)
    depth = msg.get("depth", 0)
    param_str = f"  params=[{', '.join(params)}]" if params else ""
    console.print(
        f"  [bold green][+] NODE_DISCOVERED (d={depth} s={score:.1f})[/bold green] {url}{param_str}"
    )


def _print_summary(parser: ResultParser) -> None:
    stats = parser.stats
    table = Table(
        title="SYSTEM SCAN RECAP", show_header=True, header_style="bold magenta"
    )
    table.add_column("Severity", justify="left")
    table.add_column("Count", justify="right")

    any_found = False
    for sev in ("critical", "high", "medium", "low", "info"):
        count = stats.get(sev, 0)
        if count:
            color = _SEV_COLORS.get(sev, "white")
            table.add_row(f"[{color}]{sev.upper()}[/{color}]", str(count))
            any_found = True

    if not any_found:
        table.add_row("[green]NO VULNS DETECTED[/green]", "0")

    console.print("\n")
    console.print(table)


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
    "--rps", default=None, type=float, help="Requests per second (overrides config)."
)
@click.option(
    "--rpm", default=None, type=float, help="Requests per minute (overrides rps)."
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
    default="html",
    type=click.Choice(["json", "csv", "pdf", "html"]),
    show_default=True,
)
@click.option(
    "--profile",
    default=None,
    help="Scan profile from settings.yaml (e.g. full, fast, stealth)",
)
@click.option(
    "--evasion-level",
    default="high",
    type=click.Choice(["none", "low", "high"]),
    help="Browser stealth level.",
)
@click.option(
    "--brute-auth",
    is_flag=True,
    default=False,
    help="Enable credential stuffing if breach detected.",
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
    rps: float | None,
    rpm: float | None,
    timeout: int | None,
    severity: str | None,
    output: str | None,
    fmt: str,
    profile: str | None,
    evasion_level: str,
    brute_auth: bool,
    show_nodes: bool,
    dry_run: bool,
    verbose: bool,
) -> None:
    _setup_logging(verbose)
    cfg = yaml.safe_load(SETTINGS_FILE.read_text())

    prof_cfg: dict = {}
    if profile:
        if "profiles" in cfg and profile in cfg["profiles"]:
            prof_cfg = cfg["profiles"][profile]
            console.print(f"  [cyan]Profile:[/cyan] {profile}")
        else:
            console.print(
                f"  [bold red][ERROR] Profile '{profile}' not found in {SETTINGS_FILE}[/bold red]"
            )
            sys.exit(1)

    # Conversion logic: RPM takes precedence over RPS if provided
    final_rps: float
    if rpm is not None:
        final_rps = rpm / 60.0
    else:
        final_rps = rps or float(prof_cfg.get("rps") or cfg["scan"]["default_rps"])

    effective_rpm = final_rps * 60.0

    if severity:
        sev_list = [s.strip() for s in severity.split(",")]
    elif "severity_filter" in prof_cfg:
        sev_list = prof_cfg["severity_filter"]
    else:
        sev_list = cfg["scan"]["severity_filter"]

    out_dir = Path(output) if output else ensure_dir(REPORTS_DIR)

    console.print(
        Panel(
            f"[bold cyan]Target:[/bold cyan] {target}\n[bold cyan]Speed:[/bold cyan] {final_rps:.2f} RPS ({effective_rpm:.2f} RPM)\n[bold cyan]Severities:[/bold cyan] {', '.join(sev_list)}\n[bold cyan]Evasion:[/bold cyan] {evasion_level}",
            title="Blue Whale Initialization",
            expand=False,
        )
    )

    if dry_run:
        console.print(
            "  [bold yellow][DRY RUN] Engine will not be spawned.[/bold yellow]\n"
        )

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

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )

    async def _run() -> None:
        nonlocal node_count

        task_id = progress.add_task("[cyan]Initializing Scan...", total=100)

        with progress:
            try:
                async for msg in executor.run():
                    msg_type = msg.get("type", "")

                    if msg_type == "vulnerability":
                        synthetic = {
                            "template-id": msg.get("id"),
                            "info": {
                                "name": msg.get("name"),
                                "severity": msg.get("severity"),
                            },
                            "host": target,
                            "matched-at": msg.get("url"),
                            "extracted-results": [msg.get("evidence")],
                            "fuzzing-parameter": msg.get("param"),
                            "payload": msg.get("payload"),
                        }
                        finding = parser.ingest(json.dumps(synthetic))
                        if finding:
                            _print_finding(finding)

                    elif msg_type == "loot":
                        url = msg.get("url")
                        console.print(
                            f"  [bold yellow][LOOT][/bold yellow] Extracted client-side storage from {url}"
                        )
                        if verbose:
                            console.print(f"    [dim]{msg.get('data')}[/dim]")

                    elif msg_type == "privilege_escalation":
                        subtype = msg.get("subtype")
                        token = msg.get("token")
                        source = msg.get("source_url")
                        console.print(
                            Panel(
                                f"[bold red]PRIVILEGE ESCALATION EVENT[/bold red]\n[cyan]Type:[/cyan] {subtype}\n[cyan]Token:[/cyan] {token}\n[cyan]Source:[/cyan] {source}",
                                border_style="red",
                            )
                        )

                    elif msg_type == "node":
                        node_count += 1
                        if show_nodes:
                            _print_node(msg)

                    elif msg_type == "oast_hit":
                        protocol = msg.get("protocol", "UNKNOWN")
                        identifier = msg.get("identifier", "unknown")
                        remote_addr = msg.get("remote_addr", "unknown")
                        console.print(
                            f"  [bold red][OAST HIT][/bold red] {protocol} interaction from {remote_addr} (ID: {identifier})"
                        )
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
                        status = msg.get("status", 0)
                        reflect = msg.get("reflect", False)
                        timing = msg.get("timing_hit", False)
                        if reflect:
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
                        phase = msg.get("phase", "scanning")
                        prog_val = msg.get("progress", 0)
                        detail = msg.get("detail", "")
                        if len(detail) > 40:
                            detail = detail[:37] + "..."
                        progress.update(
                            task_id,
                            completed=prog_val,
                            description=f"[bold green][{phase.upper()}][/bold green] {detail}",
                        )

                    elif msg_type == "scan_done":
                        progress.update(
                            task_id,
                            completed=100,
                            description="[bold cyan]Scan Complete[/bold cyan]",
                        )
                        total = msg.get("total_nodes", node_count)
                        console.print(
                            f"\n  [bold green]Crawl complete[/bold green] - {total} endpoints discovered."
                        )

                    elif msg_type == "error":
                        console.print(
                            f"\n  [bold red][ERROR][/bold red] {msg.get('message', '')}"
                        )

                    elif msg_type == "dry_run":
                        console.print(
                            f"  [yellow]DRY RUN: would scan {msg.get('target')} (job {msg.get('job_id')})[/yellow]"
                        )

            except Exception as e:
                console.print(f"\n  [bold red]Execution failed:[/bold red] {e}")

    asyncio.run(_run())

    _print_summary(parser)

    if not dry_run:
        # Always export JSONL for raw data persistence
        json_path = out_dir / f"whale_{executor.job_id}.jsonl"
        parser.export_jsonl(json_path)
        console.print(f"\n  [cyan]Raw JSONL results[/cyan] -> {json_path}")

        # Always export HTML for human readability
        reporter = Reporter(target=target, job_id=executor.job_id)
        reporter.load_from_parser(parser)
        html_path = reporter.export_html(out_dir)
        console.print(f"  [cyan]HTML report[/cyan]       -> {html_path}")

        if fmt == "csv":
            path = parser.export_csv(out_dir / f"whale_{executor.job_id}.csv")
            console.print(f"  [cyan]CSV export[/cyan]        -> {path}")
        elif fmt == "pdf":
            path = reporter.export_pdf(out_dir)
            if path:
                console.print(f"  [cyan]PDF report[/cyan]        -> {path}")
            else:
                console.print(
                    "\n  [red]PDF generation failed (install weasyprint).[/red]"
                )


@cli.command("report")
@click.argument("results_file", type=click.Path(exists=True, path_type=Path))
@click.option("--target", default="unknown", help="Target URL label for the report.")
@click.option("--output", "-o", default=None, help="Output directory for the report.")
@click.option(
    "--format", "fmt", default="pdf", type=click.Choice(["pdf"]), show_default=True
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
    sev_list = [s.strip() for s in severity.split(",")] if severity else None
    out_dir = Path(output) if output else ensure_dir(REPORTS_DIR)

    console.print(
        f"  [cyan]Generating {fmt.upper()} report from {results_file}...[/cyan]"
    )
    parser = ResultParser.from_file(results_file, severity_filter=sev_list)
    reporter = Reporter(target=target, job_id=results_file.stem)
    reporter.load_from_parser(parser)

    path = reporter.export_pdf(out_dir)
    if path:
        console.print(f"  [bold green]Report saved[/bold green] -> {path}")
    else:
        console.print("  [bold red]Report generation failed.[/bold red]")
        sys.exit(1)


@cli.command("bootstrap")
@click.option(
    "--force", is_flag=True, default=False, help="Rebuild engine even if binary exists."
)
def cmd_bootstrap(force: bool) -> None:
    args = ["bash", str(BOOTSTRAP_SCRIPT)]
    if force:
        args.append("--force")
    result = subprocess.run(args, check=False)
    sys.exit(result.returncode)


@cli.command("paths")
def cmd_paths() -> None:
    console.print(
        Panel("[bold cyan]Blue Whale Path Resolution[/bold cyan]", expand=False)
    )
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Status")
    table.add_column("Name")
    table.add_column("Path")

    for name, p in all_paths().items():
        status = (
            "[bold green][OK][/bold green]"
            if p.exists()
            else "[bold red][XX][/bold red]"
        )
        table.add_row(status, name, str(p))

    console.print(table)
    console.print()
