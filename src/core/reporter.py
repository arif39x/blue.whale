from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.parser import Finding, ResultParser

logger = logging.getLogger(__name__)

class Reporter:
    def __init__(self, target: str, job_id: str = "unknown") -> None:
        self.target = target
        self.job_id = job_id
        self._findings: list[Finding] = []

    def load_from_parser(self, parser: "ResultParser") -> None:
        self._findings = parser.sorted_findings()

    def load_from_list(self, findings: list["Finding"]) -> None:
        from core.parser import _SEVERITY_RANK, Severity

        self._findings = sorted(
            findings, key=lambda f: _SEVERITY_RANK.get(f.severity, 99)
        )

    def export_txt(self, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        content = self._render_txt()
        path = output_dir / f"whale_{self.job_id}.txt"
        self._atomic_write(path, content)
        logger.info("[Reporter] Text report -> %s", path)
        return path

    def export_md(self, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        content = self._render_md()
        path = output_dir / f"whale_{self.job_id}.md"
        self._atomic_write(path, content)
        logger.info("[Reporter] Markdown report -> %s", path)
        return path

    def _render_txt(self) -> str:
        from core.parser import Severity
        
        stats = {s.value: 0 for s in Severity}
        for f in self._findings:
            stats[f.severity.value] = stats.get(f.severity.value, 0) + 1

        lines = [
            "=" * 60,
            " BLUE WHALE SECURITY AUDIT REPORT",
            "=" * 60,
            f"Target:    {self.target}",
            f"Job ID:    {self.job_id}",
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            "-" * 60,
            " EXECUTIVE SUMMARY",
            "-" * 60,
            f" CRITICAL: {stats.get('critical', 0)}",
            f" HIGH:     {stats.get('high', 0)}",
            f" MEDIUM:   {stats.get('medium', 0)}",
            f" LOW:      {stats.get('low', 0)}",
            f" INFO:     {stats.get('info', 0)}",
            "-" * 60,
            " TECHNICAL FINDINGS",
            "-" * 60,
        ]

        if not self._findings:
            lines.append(" No vulnerabilities detected.")
        else:
            for f in self._findings:
                lines.extend([
                    f" [{f.severity.value.upper()}] {f.name}",
                    f" URL:      {f.url}",
                    f" Match:    {f.matched_at}",
                    f" Template: {f.template_id}",
                    f" Proof:    {f.curl_cmd}",
                    "." * 40,
                ])

        return "\n".join(lines)

    def _render_md(self) -> str:
        from core.parser import Severity
        
        stats = {s.value: 0 for s in Severity}
        for f in self._findings:
            stats[f.severity.value] = stats.get(f.severity.value, 0) + 1

        lines = [
            f"# BlueWhale Security Report: {self.target}",
            "",
            f"- **Job ID:** `{self.job_id}`",
            f"- **Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            "",
            "## Executive Summary",
            "",
            "| Severity | Count |",
            "| :--- | :--- |",
            f"| **Critical** | {stats.get('critical', 0)} |",
            f"| **High** | {stats.get('high', 0)} |",
            f"| **Medium** | {stats.get('medium', 0)} |",
            f"| **Low** | {stats.get('low', 0)} |",
            f"| **Info** | {stats.get('info', 0)} |",
            "",
            "## Technical Findings",
            "",
        ]

        if not self._findings:
            lines.append("> No vulnerabilities detected.")
        else:
            for f in self._findings:
                lines.extend([
                    f"### {f.name} [{f.severity.value.upper()}]",
                    f"- **URL:** {f.url}",
                    f"- **Matched At:** `{f.matched_at}`",
                    f"- **Template ID:** `{f.template_id}`",
                    "- **Evidence (cURL):**",
                    "  ```bash",
                    f"  {f.curl_cmd}",
                    "  ```",
                    "",
                ])

        return "\n".join(lines)

    @staticmethod
    def _atomic_write(path: Path, content: str) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        try:
            tmp.write_text(content, encoding="utf-8")
            tmp.replace(path)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise
