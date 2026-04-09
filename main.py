from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

# project root is on sys.path regardless of CWD
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
_ROOT = Path(__file__).resolve().parent
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
    # sys.argv includes the script name itself real args start at index 1.
    if len(sys.argv) > 1:
        _launch_cli()
    else:
        _launch_gui()


_BANNER = r"""\033[36m
  ___ _    _   _ ___  __      _____  _  _ ___ _    ___ 
 | _ ) |  | | | | __| \ \    / / _ \| || | _ | |  | __|
 | _ \ |__| |_| | _|   \ \/\/ /| _ \ |__| _ \ |__| _| 
 |___/____|\___/|___|   \_/\_/ |_||_|_||_|_||______|___|
\033[0m"""


def _launch_cli() -> None:
    # Delegate all CLI work to the Click command group.
    if any(arg in sys.argv for arg in ["-h", "--help", "help"]):
        print(_BANNER)

    from cli.commands import cli

    cli(standalone_mode=True)


def _launch_gui() -> None:
    try:
        from PyQt6.QtGui import QIcon
        from PyQt6.QtWidgets import QApplication

        from gui.dashboard import Dashboard
    except ImportError as exc:
        logger.critical(
            "PyQt6 is not installed. Install it with:\n"
            "  pip install PyQt6\n"
            "Or run in CLI mode:  python main.py --help\n\n"
            "Original error: %s",
            exc,
        )
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setApplicationName("Blue Whale")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("Blue Whale")

    os.environ.setdefault("QT_AUTO_SCREEN_SCALE_FACTOR", "1")

    window = Dashboard()
    window.show()

    logger.info("Blue Whale GUI launched.")
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
