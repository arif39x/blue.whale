from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

# project root and src are on sys.path
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
_ROOT = Path(__file__).resolve().parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# create mandatory directories on every startup
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
from core.paths import REPORTS_DIR, TMP_DIR, ensure_dir  # noqa: E402

ensure_dir(TMP_DIR)
ensure_dir(REPORTS_DIR)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("whale")


def main() -> None:
    # Delegate all work to the Click command group in cli/commands.py
    if len(sys.argv) == 1:
        print(_BANNER)
        from cli.commands import cli
        try:
            cli(args=["--help"], standalone_mode=True)
        except SystemExit:
            pass
    else:
        if any(arg in sys.argv for arg in ["-h", "--help", "help"]):
            print(_BANNER)

        from cli.commands import cli
        cli(standalone_mode=True)


_BANNER = r"""\033[32m
██████╗ ██╗     ██╗   ██╗███████╗    ██╗    ██╗██╗  ██╗ █████╗ ██╗     ███████╗
██╔══██╗██║     ██║   ██║██╔════╝    ██║    ██║██║  ██║██╔══██╗██║     ██╔════╝
██████╔╝██║     ██║   ██║█████╗      ██║ █ ║██║███████║███████║██║     █████╗
██╔══██╗██║     ██║   ██║██╔══╝      ██║███╗██║██╔══██║██╔══██║██║     ██╔══╝
██████╔╝███████╗╚██████╔╝███████╗    ╚███╔███╔╝██║  ██║██║  ██║███████╗███████╗
╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝     ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝
\033[0m"""


if __name__ == "__main__":
    main()
