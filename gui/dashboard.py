from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import QObject, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QIcon
from PyQt6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMenu,
    QMenuBar,
    QPlainTextEdit,
    QSizePolicy,
    QSplitter,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.executor import ScanExecutor
from core.parser import Finding, ResultParser
from core.paths import REPORTS_DIR, ensure_dir
from core.reporter import Reporter
from gui.components import PALETTE, SEV_COLOURS, ScanControl, SeverityBadge, StatCard

logger = logging.getLogger(__name__)

_SEVERITIES = ("critical", "high", "medium", "low", "info")
_TABLE_COLS = ("Severity", "Name", "URL", "Matched At", "Template")


class _Bridge(QObject):
    # Emits signals that are safe to receive in the Qt main thread.

    finding_found = pyqtSignal(object)  # Finding
    log_message = pyqtSignal(str)
    scan_finished = pyqtSignal()


class Dashboard(QMainWindow):


    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Blue Whale")
        self.setMinimumSize(1100, 700)
        self._apply_dark_palette()

        # State
        self._executor: Optional[ScanExecutor] = None
        self._parser: Optional[ResultParser] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._scan_thread: Optional[threading.Thread] = None

        # Bridge
        self._bridge = _Bridge()
        self._bridge.finding_found.connect(self._on_finding)
        self._bridge.log_message.connect(self._on_log)
        self._bridge.scan_finished.connect(self._on_scan_finished)

        self._build_ui()
        self._build_menu()

    def _build_ui(self) -> None:
        root = QWidget()
        root.setStyleSheet(f"background: {PALETTE['bg']}; color: {PALETTE['text']};")
        self.setCentralWidget(root)

        vbox = QVBoxLayout(root)
        vbox.setContentsMargins(16, 12, 16, 12)
        vbox.setSpacing(12)

        # ── Header ──
        header = QLabel("  Blue Whale")
        header.setStyleSheet(
            "font-size: 20px; font-weight: 700; color: #e6edf3;"
            " letter-spacing: 1px; border: none;"
        )
        vbox.addWidget(header)

        # Scan Control 
        self._ctrl = ScanControl()
        self._ctrl.start_btn.clicked.connect(self._start_scan)
        self._ctrl.stop_btn.clicked.connect(self._stop_scan)
        vbox.addWidget(self._ctrl)

        # Stat Cards 
        card_row = QHBoxLayout()
        card_row.setSpacing(8)
        self._stat_cards: dict[str, StatCard] = {}
        for sev in _SEVERITIES:
            card = StatCard(sev)
            card_row.addWidget(card)
            self._stat_cards[sev] = card
        card_row.addStretch()
        vbox.addLayout(card_row)

        # table / log 
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setStyleSheet(f"background: {PALETTE['bg']};")

        # Findings table
        self._table = QTableWidget(0, len(_TABLE_COLS))
        self._table.setHorizontalHeaderLabels(_TABLE_COLS)
        self._table.setStyleSheet(
            f"QTableWidget {{ background: {PALETTE['surface']}; color: {PALETTE['text']};"
            f" gridline-color: {PALETTE['border']}; font-size: 12px; border: none; }}"
            f"QHeaderView::section {{ background: {PALETTE['surface']}; color: {PALETTE['muted']};"
            f" font-size: 10px; text-transform: uppercase; letter-spacing: 1px;"
            f" padding: 6px 8px; border-bottom: 1px solid {PALETTE['border']}; }}"
            f"QTableWidget::item {{ padding: 6px 8px; }}"
            f"QTableWidget::item:selected {{ background: {PALETTE['accent']}20; }}"
        )
        self._table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSortingEnabled(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(True)

        # Log feed
        self._log = QPlainTextEdit()
        self._log.setReadOnly(True)
        self._log.setMaximumBlockCount(2000)
        self._log.setStyleSheet(
            f"background: {PALETTE['surface']}; color: {PALETTE['muted']};"
            " font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 11px;"
            f" border: 1px solid {PALETTE['border']}; border-radius: 6px; padding: 6px;"
        )
        self._log.setFixedHeight(160)

        splitter.addWidget(self._table)
        splitter.addWidget(self._log)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)

        vbox.addWidget(splitter, stretch=1)

        # Status bar 
        sb = QStatusBar()
        sb.setStyleSheet(f"color: {PALETTE['muted']}; font-size: 11px;")
        self._status_label = QLabel("Ready.")
        sb.addWidget(self._status_label)
        self.setStatusBar(sb)

    def _build_menu(self) -> None:
        mb = self.menuBar()
        mb.setStyleSheet(
            f"background: {PALETTE['surface']}; color: {PALETTE['text']};"
            f" border-bottom: 1px solid {PALETTE['border']};"
        )

        file_menu: QMenu = mb.addMenu("File")
        file_menu.setStyleSheet(
            f"background: {PALETTE['surface']}; color: {PALETTE['text']};"
        )

        export_html = file_menu.addAction("Export HTML Report")
        export_html.triggered.connect(self._export_html)

        export_json = file_menu.addAction("Export JSONL")
        export_json.triggered.connect(self._export_jsonl)

        export_pdf = file_menu.addAction("Export PDF Report")
        export_pdf.triggered.connect(self._export_pdf)

        file_menu.addSeparator()
        quit_act = file_menu.addAction("Quit")
        quit_act.triggered.connect(QApplication.quit)


    def _start_scan(self) -> None:
        target = self._ctrl.target_input.text().strip()
        if not target:
            self._log_msg("  Please enter a target URL.")
            return

        header = self._ctrl.header_input.text().strip()
        header = header if header else None

        rps = self._ctrl.rps_spinner.value()
        self._clear_results()
        self._ctrl.start_btn.setEnabled(False)
        self._ctrl.stop_btn.setEnabled(True)
        self._status_label.setText(f"Scanning {target}…")
        self._log_msg(f" Scan started → {target}  (RPS={rps})")

        self._parser = ResultParser()
        self._executor = ScanExecutor(target=target, header=header, rps=rps)

        # Run asyncio event loop in a background thread
        self._loop = asyncio.new_event_loop()
        self._scan_thread = threading.Thread(target=self._run_async_scan, daemon=True)
        self._scan_thread.start()

    def _run_async_scan(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._async_scan_worker())
        self._loop.close()

    async def _async_scan_worker(self) -> None:
        assert self._executor and self._parser
        async for line in self._executor.run():
            finding = self._parser.ingest(line)
            if finding:
                self._bridge.finding_found.emit(finding)
            else:
                # Emit raw log lines too
                self._bridge.log_message.emit(line[:200])
        self._bridge.scan_finished.emit()

    def _stop_scan(self) -> None:
        if self._executor and self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self._executor.cancel(), self._loop)
        self._log_msg(" Scan stopped by user.")
        self._on_scan_finished()

    # Signal handlers (Qt main thread)

    def _on_finding(self, finding: Finding) -> None:
        self._add_table_row(finding)
        counts = self._parser.stats if self._parser else {}
        for sev, card in self._stat_cards.items():
            card.set_count(counts.get(sev, 0))

    def _on_log(self, msg: str) -> None:
        self._log_msg(msg)

    def _on_scan_finished(self) -> None:
        self._ctrl.start_btn.setEnabled(True)
        self._ctrl.stop_btn.setEnabled(False)
        total = sum(c.count() for c in self._stat_cards.values()) if self._parser else 0
        self._status_label.setText(
            f"Scan complete — {len(self._parser.sorted_findings()) if self._parser else 0} findings."
        )
        self._log_msg("DONE  Scan finished.")

    # Table helpers
    

    def _add_table_row(self, finding: Finding) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)

        # Severity column use SeverityBadge widget
        sev_widget = QWidget()
        sev_layout = QHBoxLayout(sev_widget)
        sev_layout.setContentsMargins(4, 2, 4, 2)
        sev_layout.addWidget(SeverityBadge(finding.severity.value))
        sev_layout.addStretch()
        self._table.setCellWidget(row, 0, sev_widget)

        values = [finding.name, finding.url, finding.matched_at, finding.template_id]
        colour = SEV_COLOURS.get(finding.severity.value, PALETTE["muted"])
        for col, val in enumerate(values, start=1):
            item = QTableWidgetItem(val)
            item.setForeground(QColor(PALETTE["text"]))
            self._table.setItem(row, col, item)

        self._table.scrollToBottom()

    def _clear_results(self) -> None:
        self._table.setRowCount(0)
        self._log.clear()
        for card in self._stat_cards.values():
            card.set_count(0)



    def _export_html(self) -> None:
        if not self._parser or not self._parser.sorted_findings():
            self._log_msg("No findings to export.")
            return
        out, _ = QFileDialog.getSaveFileName(
            self, "Save HTML Report", "", "HTML Files (*.html)"
        )
        if out:
            reporter = Reporter(
                target=self._ctrl.target_input.text(),
                job_id=self._executor.job_id if self._executor else "export",
            )
            reporter.load_from_parser(self._parser)
            path = reporter.export_html(Path(out).parent)
            self._log_msg(f"  HTML report saved → {path}")

    def _export_jsonl(self) -> None:
        if not self._parser or not self._parser.sorted_findings():
            self._log_msg("No findings to export.")
            return
        out, _ = QFileDialog.getSaveFileName(
            self, "Save JSONL Export", "", "JSONL Files (*.jsonl)"
        )
        if out:
            path = self._parser.export_jsonl(Path(out))
            self._log_msg(f"  JSONL export saved → {path}")

    def _export_pdf(self) -> None:
        if not self._parser or not self._parser.sorted_findings():
            self._log_msg("No findings to export.")
            return
        out, _ = QFileDialog.getSaveFileName(
            self, "Save PDF Report", "", "PDF Files (*.pdf)"
        )
        if out:
            reporter = Reporter(
                target=self._ctrl.target_input.text(),
                job_id=self._executor.job_id if self._executor else "export",
            )
            reporter.load_from_parser(self._parser)
            path = reporter.export_pdf(Path(out).parent)
            if path:
                self._log_msg(f"  PDF report saved → {path}")
            else:
                self._log_msg("  PDF generation failed (WeasyPrint missing?).")



    def _log_msg(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._log.appendPlainText(f"[{ts}]  {msg}")

    def _apply_dark_palette(self) -> None:
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{
                background-color: {PALETTE["bg"]};
                color: {PALETTE["text"]};
                font-family: 'Segoe UI', system-ui, sans-serif;
            }}
            QScrollBar:vertical {{
                background: {PALETTE["surface"]}; width: 10px; border-radius: 5px;
            }}
            QScrollBar::handle:vertical {{
                background: {PALETTE["border"]}; border-radius: 5px; min-height: 30px;
            }}
        """)
