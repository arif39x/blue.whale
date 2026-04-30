from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent.parent

CONFIG_DIR: Path = PROJECT_ROOT / "config"
CORE_DIR: Path = PROJECT_ROOT / "src" / "core"
SH_DIR: Path = PROJECT_ROOT / "sh"
BIN_DIR: Path = PROJECT_ROOT / "bin"
DATA_DIR: Path = PROJECT_ROOT / "data"
TMP_DIR: Path = DATA_DIR / "tmp"
REPORTS_DIR: Path = PROJECT_ROOT / "reports"

SETTINGS_FILE: Path = CONFIG_DIR / "settings.yaml"

USER_AGENTS_FILE: Path = DATA_DIR / "user_agents.txt"

BOOTSTRAP_SCRIPT: Path = SH_DIR / "bootstrap.sh"

ENGINE_BINARY: Path = BIN_DIR / "whale-engine"
BRAIN_BINARY: Path = BIN_DIR / "whale-brain"

def require(path: Path) -> Path:

    if not path.exists():
        raise FileNotFoundError(
            f"[Blue Whale] Required path not found: {path}\n"
            f"  -> Ensure you have run 'python main.py bootstrap' first, "
            f"or check {SETTINGS_FILE} for misconfiguration."
        )
    return path

def ensure_dir(path: Path) -> Path:

    path.mkdir(parents=True, exist_ok=True)
    return path

def all_paths() -> dict[str, Path]:

    return {
        "PROJECT_ROOT": PROJECT_ROOT,
        "CONFIG_DIR": CONFIG_DIR,
        "SH_DIR": SH_DIR,
        "BIN_DIR": BIN_DIR,
        "DATA_DIR": DATA_DIR,
        "TMP_DIR": TMP_DIR,
        "REPORTS_DIR": REPORTS_DIR,
        "SETTINGS_FILE": SETTINGS_FILE,
        "USER_AGENTS_FILE": USER_AGENTS_FILE,
        "BOOTSTRAP_SCRIPT": BOOTSTRAP_SCRIPT,
        "ENGINE_BINARY": ENGINE_BINARY,
        "BRAIN_BINARY": BRAIN_BINARY,
    }

if __name__ == "__main__":
    for name, p in all_paths().items():
        status = "[OK]" if p.exists() else "[MISSING]"
        print(f"  {status}  {name:20s}  {p}")
