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

PALETTE = {
    "bg": "#000000",          # Pure black
    "surface": "#050505",     # Near black
    "border": "#00ff41",      # Matrix Green
    "text": "#00ff41",        # Neon Green
    "muted": "#008f11",       # Darker Green
    "critical": "#ff0000",    # Pure Red
    "high": "#ff8c00",        # Dark Orange
    "medium": "#ffff00",      # Yellow
    "low": "#00ff41",         # Green
    "info": "#00bfff",        # Deep Sky Blue
    "accent": "#00ff41",      # Neon Green
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



class SeverityBadge(QLabel):

    def __init__(self, severity: str, parent: QWidget | None = None) -> None:
        super().__init__(severity.upper(), parent)
        colour = severity_colour(severity)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFixedSize(80, 22)
        self.setStyleSheet(
            f"color: {colour}; background: {colour}20; border: 1px solid {colour}50;"
            " border-radius: 4px; font-size: 10px; font-weight: bold;"
        )




class StatCard(QFrame):
    # A small card showing a count and a severity label.

    def __init__(self, severity: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._severity = severity
        colour = severity_colour(severity)

        self.setFixedWidth(100)
        self.setStyleSheet(
            f"background: {PALETTE['bg']}; border: 1px solid {colour}40;"
            " border-radius: 0px;" # Squared for hacker look
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(2)

        self._count_label = QLabel("0")
        self._count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._count_label.setStyleSheet(
            f"color: {colour}; font-family: 'Courier New', 'Consolas', monospace;"
            " font-size: 26px; font-weight: 700; border: none;"
        )

        sev_label = QLabel(severity.upper())
        sev_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sev_label.setStyleSheet(
            f"color: {PALETTE['muted']}; font-family: 'Courier New', 'Consolas', monospace;"
            " font-size: 9px; letter-spacing: 2px; border: none;"
        )

        layout.addWidget(self._count_label)
        layout.addWidget(sev_label)

    def set_count(self, n: int) -> None:
        self._count_label.setText(str(n))

    def count(self) -> int:
        return int(self._count_label.text())




class ScanControl(QWidget):
    # Target URL input + RPS spinner + Start/Stop buttons.

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # Target input
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("target_url")
        self.target_input.setStyleSheet(
            f"background: #000; color: {PALETTE['text']};"
            f" border: 1px solid {PALETTE['border']}; border-radius: 0px;"
            " padding: 6px 10px; font-family: 'Courier New', monospace; font-size: 13px;"
        )
        self.target_input.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )

        # Header input
        self.header_input = QLineEdit()
        self.header_input.setPlaceholderText("custom_headers")
        self.header_input.setStyleSheet(
            f"background: #000; color: {PALETTE['text']};"
            f" border: 1px solid {PALETTE['border']}; border-radius: 0px;"
            " padding: 6px 10px; font-family: 'Courier New', monospace; font-size: 13px;"
        )
        self.header_input.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )

        # RPS spinner
        rps_label = QLabel("RPM")
        rps_label.setStyleSheet(f"color: {PALETTE['muted']}; font-family: 'Courier New', monospace; font-size: 12px;")
        self.rps_spinner = QSpinBox()
        self.rps_spinner.setRange(1, 500)
        self.rps_spinner.setValue(10)
        self.rps_spinner.setFixedWidth(60)
        self.rps_spinner.setStyleSheet(
            f"background: #000; color: {PALETTE['text']};"
            f" border: 1px solid {PALETTE['border']}; border-radius: 0px; padding: 4px;"
            " font-family: 'Courier New', monospace;"
        )

        # Buttons
        self.start_btn = QPushButton("> INITIALIZE_SCAN")
        self.start_btn.setFixedHeight(34)
        self.start_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.start_btn.setStyleSheet(
            f"QPushButton {{ background: #000; color: {PALETTE['accent']};"
            f" border: 1px solid {PALETTE['accent']}; border-radius: 0px;"
            " font-family: 'Courier New', monospace; font-size: 13px; font-weight: 900; padding: 0 16px; }"
            f" QPushButton:hover {{ background: {PALETTE['accent']}30; }}"
        )

        self.stop_btn = QPushButton("! ABORT")
        self.stop_btn.setFixedHeight(34)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.stop_btn.setStyleSheet(
            f"background: #000; color: {PALETTE['critical']};"
            f" border: 1px solid {PALETTE['critical']}; border-radius: 0px;"
            " font-family: 'Courier New', monospace; font-size: 13px; font-weight: 900; padding: 0 16px;"
        )

        layout.addWidget(self.target_input)
        layout.addWidget(self.header_input)
        layout.addWidget(rps_label)
        layout.addWidget(self.rps_spinner)
        layout.addWidget(self.start_btn)
        layout.addWidget(self.stop_btn)
