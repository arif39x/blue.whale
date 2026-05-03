from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import click
from rich.console import Console

from core.paths import PROJECT_ROOT, SETTINGS_FILE, ensure_dir

console = Console()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option("5.0.0", prog_name="BlueWhale")
def cli() -> None:
    pass


@cli.command("init")
@click.option(
    "--dir", "workdir", type=click.Path(), default=".", help="Directory to initialize"
)
def init(workdir: str) -> None:
    path = Path(workdir)
    ensure_dir(path / "config")
    ensure_dir(path / "data" / "evidence")
    ensure_dir(path / "reports")

    settings_dest = path / "config" / "settings.yaml"
    if not settings_dest.exists():
        import shutil

        src_settings = PROJECT_ROOT / "config" / "settings.yaml"
        if src_settings.exists():
            shutil.copy(src_settings, settings_dest)
            console.print(f"[green][+][/green] Created {settings_dest}")

    console.print("[bold green]BlueWhale workspace initialized.[/bold green]")


@cli.command("scan")
@click.option("--target", "-t", required=True, help="Target URL")
@click.option(
    "--config", "-c", type=click.Path(exists=True), help="Path to config file"
)
@click.option("--no-llm", is_flag=True, help="Disable LLM augmentation")
def scan(target: str, config: str | None, no_llm: bool) -> None:
    """Perform endpoint probing and rule-based detection."""
    console.print(f"[bold blue]Starting scan on {target}...[/bold blue]")
    from src.core.orchestrator import Orchestrator

    orch = Orchestrator(Path("."))
    asyncio.run(orch.run_scan(target))


@cli.command("crawl")
@click.option("--target", "-t", required=True, help="Target URL")
@click.option("--depth", default=3, help="Crawl depth")
def crawl(target: str, depth: int) -> None:
    console.print(f"[bold blue]Crawling {target} (depth={depth})...[/bold blue]")


@cli.command("auth")
@click.option("--target", "-t", required=True, help="Target URL")
@click.option("--roles", help="Comma-separated roles to test")
def auth(target: str, roles: str | None) -> None:
    console.print(
        f"[bold blue]Testing authentication boundaries on {target}...[/bold blue]"
    )


@cli.command("oast")
@click.option("--domain", help="OAST domain")
def oast(domain: str | None) -> None:
    console.print("[bold blue]Starting OAST listener...[/bold blue]")
    # Implementation will call core.orchestrator.run_oast


@cli.command("loot")
@click.option("--target", "-t", required=True, help="Target URL")
def loot(target: str) -> None:
    """Extract localStorage, IndexedDB, and hidden endpoints."""
    console.print(f"[bold blue]Looting {target}...[/bold blue]")
    # Implementation will call core.orchestrator.run_loot


@cli.command("analyze")
@click.option("--no-llm", is_flag=True, help="Disable LLM analysis")
@click.option("--model", help="Model adapter to use")
def analyze(no_llm: bool, model: str | None) -> None:
    """Perform evidence classification and triage."""
    console.print("[bold blue]Analyzing evidence...[/bold blue]")
    import yaml

    from core.paths import SETTINGS_FILE, TMP_DIR
    from src.core.orchestrator import Orchestrator
    from src.models.base import DisabledAdapter
    from src.models.ollama import OllamaAdapter

    adapter = DisabledAdapter()
    if not no_llm:
        with open(SETTINGS_FILE) as f:
            cfg = yaml.safe_load(f)
            llm_cfg = cfg.get("llm", {})

            # Use detected models if not explicitly provided
            explicit_models = [model] if model else llm_cfg.get("models")

            adapter = OllamaAdapter(
                ollama_url=llm_cfg.get("ollama_url", "http://localhost:11434"),
                models=explicit_models,
                socket_path=TMP_DIR / "brain.sock",
            )

    orch = Orchestrator(Path("."), model_adapter=adapter)
    asyncio.run(orch.run_analyze())


@cli.command("report")
@click.option("--format", type=click.Choice(["json", "html", "sarif"]), default="json")
@click.option("--output", "-o", help="Output file/directory")
def report(format: str, output: str | None) -> None:
    """Generate vulnerability reports."""
    console.print(f"[bold blue]Generating {format} report...[/bold blue]")
    from src.core.orchestrator import Orchestrator

    orch = Orchestrator(Path("."))
    asyncio.run(orch.generate_report(format))


@cli.command("bootstrap")
@click.option("--force", is_flag=True, help="Force recompile")
def bootstrap(force: bool) -> None:
    """Bootstrap Triple-Core (compile Go and Rust binaries)."""
    import subprocess

    from core.paths import BOOTSTRAP_SCRIPT

    cmd = [str(BOOTSTRAP_SCRIPT)]
    if force:
        cmd.append("--force")
    subprocess.run(cmd)


if __name__ == "__main__":
    cli()
