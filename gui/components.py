from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont, QPalette
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

# ---------------------------------------------------------------------------
# Colour palette (matches reporter HTML theme)
# ---------------------------------------------------------------------------
PALETTE = {
    "bg": "#0d1117",
    "surface": "#161b22",
    "border": "#30363d",
    "text": "#e6edf3",
    "muted": "#8b949e",
    "critical": "#f85149",
    "high": "#f0883e",
    "medium": "#d29922",
    "low": "#3fb950",
    "info": "#58a6ff",
    "accent": "#1f6feb",
}

SEV_COLOURS: dict[str, str] = {
    "critical": PALETTE["critical"],
    "high": PALETTE["high"],
    "medium": PALETTE["medium"],
    "low": PALETTE["low"],
    "info": PALETTE["info"],
}


def severity_colour(sev: str) -> str:
    return SEV_COLOURS.get(sev.lower(), PALETTE["muted"])


# ---------------------------------------------------------------------------
# SeverityBadge
# ---------------------------------------------------------------------------


class SeverityBadge(QLabel):
    # A styled pill-shaped label showing a severity level.

    def __init__(self, severity: str, parent: QWidget | None = None) -> None:
        super().__init__(severity.upper(), parent)
        colour = severity_colour(severity)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFixedSize(80, 22)
        self.setStyleSheet(
            f"color: {colour}; background: {colour}20; border: 1px solid {colour}50;"
            " border-radius: 4px; font-size: 10px; font-weight: bold;"
        )


# ---------------------------------------------------------------------------
# StatCard
# ---------------------------------------------------------------------------


class StatCard(QFrame):
    # A small card showing a count and a severity label.

    def __init__(self, severity: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._severity = severity
        colour = severity_colour(severity)

        self.setFixedWidth(100)
        self.setStyleSheet(
            f"background: {PALETTE['surface']}; border: 1px solid {PALETTE['border']};"
            " border-radius: 8px;"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(2)

        self._count_label = QLabel("0")
        self._count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._count_label.setStyleSheet(
            f"color: {colour}; font-size: 26px; font-weight: 700; border: none;"
        )

        sev_label = QLabel(severity.upper())
        sev_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sev_label.setStyleSheet(
            f"color: {PALETTE['muted']}; font-size: 9px; letter-spacing: 1px; border: none;"
        )

        layout.addWidget(self._count_label)
        layout.addWidget(sev_label)

    def set_count(self, n: int) -> None:
        self._count_label.setText(str(n))

    def count(self) -> int:
        return int(self._count_label.text())


# ---------------------------------------------------------------------------
# ScanControl toolbar
# ---------------------------------------------------------------------------


class ScanControl(QWidget):
    # Target URL input + RPS spinner + Start/Stop buttons.

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # Target input
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("https://target.example.com")
        self.target_input.setStyleSheet(
            f"background: {PALETTE['surface']}; color: {PALETTE['text']};"
            f" border: 1px solid {PALETTE['border']}; border-radius: 6px;"
            " padding: 6px 10px; font-size: 13px;"
        )
        self.target_input.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )

        # RPS spinner
        rps_label = QLabel("RPS")
        rps_label.setStyleSheet(f"color: {PALETTE['muted']}; font-size: 12px;")
        self.rps_spinner = QSpinBox()
        self.rps_spinner.setRange(1, 500)
        self.rps_spinner.setValue(10)
        self.rps_spinner.setFixedWidth(60)
        self.rps_spinner.setStyleSheet(
            f"background: {PALETTE['surface']}; color: {PALETTE['text']};"
            f" border: 1px solid {PALETTE['border']}; border-radius: 6px; padding: 4px;"
        )

        # Buttons
        self.start_btn = QPushButton(" Start Scan")
        self.start_btn.setFixedHeight(34)
        self.start_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.start_btn.setStyleSheet(
            f"QPushButton {{ background: {PALETTE['accent']}; color: #fff;"
            " border: none; border-radius: 6px; font-size: 13px; font-weight: 600; padding: 0 16px; }"
            f" QPushButton:hover {{ background: #388bfd; }}"
        )

        self.stop_btn = QPushButton("  Stop")
        self.stop_btn.setFixedHeight(34)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.stop_btn.setStyleSheet(
            f"background: {PALETTE['surface']}; color: {PALETTE['critical']};"
            f" border: 1px solid {PALETTE['critical']}40; border-radius: 6px;"
            " font-size: 13px; font-weight: 600; padding: 0 16px;"
        )

        layout.addWidget(self.target_input)
        layout.addWidget(rps_label)
        layout.addWidget(self.rps_spinner)
        layout.addWidget(self.start_btn)
        layout.addWidget(self.stop_btn)
