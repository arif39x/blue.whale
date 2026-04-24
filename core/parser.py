from __future__ import annotations

import csv
import json
import logging
import mmap
import os
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Iterable, Iterator

from pydantic import BaseModel, Field, HttpUrl, field_validator

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
    Severity.UNKNOWN: 5,
}


class Finding(BaseModel):

    template_id: str = Field(..., alias="template-id")
    name: str
    severity: Severity = Severity.UNKNOWN
    url: str                        # matched URL / endpoint
    matched_at: str = ""            # matched sub-path / parameter
    curl_cmd: str = ""              # reproducible cURL evidence
    status_code: int | None = Field(default=None, alias="status-code")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    extra: dict = Field(default_factory=dict)

    model_config = {"populate_by_name": True}

    @field_validator("severity", mode="before")
    @classmethod
    def normalise_severity(cls, v: object) -> str:
        if isinstance(v, str):
            normalised = v.lower()
            valid = {s.value for s in Severity}
            return normalised if normalised in valid else "unknown"
        return "unknown"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK.get(self.severity, 99)

    def to_dict(self) -> dict:
        d = self.model_dump(mode="json", by_alias=False)
        d["timestamp"] = self.timestamp.isoformat()
        return d


def _nuclei_line_to_finding(raw: dict) -> Finding | None:
    # Map a raw Nuclei JSON dict to a Finding model.

    try:
        import shlex
        # Build a reproducible curl command as evidence
        method = raw.get("request", {}).get("method", "GET")
        url = raw.get("matched-at") or raw.get("host", "")
        headers = raw.get("request", {}).get("headers", {})
        
        header_flags = []
        for k, v in headers.items():
            header_flags.append(f'-H {shlex.quote(f"{k}: {v}")}')
            
        header_str = " ".join(header_flags)
        curl_cmd = f"curl -s -X {shlex.quote(method)} {header_str} {shlex.quote(url)}"

        info = raw.get("info", {})
        return Finding(
            **{
                "template-id": raw.get("template-id", "unknown"),
                "name": info.get("name", raw.get("template-id", "unknown")),
                "severity": info.get("severity", "unknown"),
                "url": raw.get("host", url),
                "matched_at": raw.get("matched-at", ""),
                "curl_cmd": curl_cmd,
                "status-code": raw.get("status-code"),
                "extra": {k: v for k, v in raw.items() if k not in (
                    "template-id", "info", "matched-at", "host", "status-code",
                    "request", "response",
                )},
            }
        )
    except Exception as exc:
        logger.debug("Could not parse finding: %s - %s", raw, exc)
        return None


class ResultParser:
    def __init__(self, severity_filter: list[str] | None = None) -> None:
        self._severity_filter: set[str] = set(severity_filter or [s.value for s in Severity])
        self._findings: list[Finding] = []
        self._seen_urls: set[str] = set()   # O(1) de-duplication key space


    def ingest(self, line: str) -> Finding | None:
        # Parse one JSON line. Returns a new Finding if valid and not a duplicate,
        # else None.

        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            logger.debug("Non-JSON line skipped: %s", line[:120])
            return None

        finding = _nuclei_line_to_finding(raw)
        if finding is None:
            return None

        if finding.severity.value not in self._severity_filter:
            return None

        dedup_key = f"{finding.template_id}::{finding.url}::{finding.matched_at}"
        if dedup_key in self._seen_urls:
            return None

        self._seen_urls.add(dedup_key)
        self._findings.append(finding)
        logger.info("[Parser] +%s %s -> %s", finding.severity.value.upper(), finding.name, finding.url)
        return finding


    def sorted_findings(self) -> list[Finding]:
    # Return findings sorted by severity (critical first).

        return sorted(self._findings, key=lambda f: f.rank)

    def by_severity(self, sev: str) -> list[Finding]:
        return [f for f in self._findings if f.severity.value == sev]

    @property
    def stats(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self._findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def export_jsonl(self, path: Path) -> Path:

        return self._atomic_write(
            path,
            "\n".join(json.dumps(f.to_dict()) for f in self.sorted_findings()) + "\n",
        )

    def export_csv(self, path: Path) -> Path:
    # Write all findings as CSV (atomic).

        import io
        buf = io.StringIO()
        fields = ["severity", "name", "url", "matched_at", "template_id", "curl_cmd", "timestamp"]
        writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for f in self.sorted_findings():
            writer.writerow({k: getattr(f, k, "") for k in fields})
        return self._atomic_write(path, buf.getvalue())

    @staticmethod
    def _atomic_write(path: Path, content: str) -> Path:
        # Write-to-temp-and-rename to prevent partial writes / corruption.

        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        try:
            tmp.write_text(content, encoding="utf-8")
            tmp.replace(path)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise
        logger.info("[Parser] Exported -> %s", path)
        return path

    @classmethod
    def from_file(cls, path: Path, severity_filter: list[str] | None = None) -> "ResultParser":

        parser = cls(severity_filter=severity_filter)
        with open(path, "rb") as fh:
            mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
            for raw_line in iter(mm.readline, b""):
                decoded = raw_line.decode(errors="replace").strip()
                if not decoded:
                    continue
                try:
                    data = json.loads(decoded)
                except json.JSONDecodeError:
                    continue

                # Try loading as an already-exported Finding dict (Python keys)
                if "template_id" in data and "url" in data:
                    try:
                        # Map python-style keys back to alias-style for Finding
                        finding = Finding(
                            **{
                                "template-id": data.get("template_id", "unknown"),
                                "name": data.get("name", "unknown"),
                                "severity": data.get("severity", "unknown"),
                                "url": data.get("url", ""),
                                "matched_at": data.get("matched_at", ""),
                                "curl_cmd": data.get("curl_cmd", ""),
                                "status-code": data.get("status_code"),
                            }
                        )
                        sev = finding.severity.value
                        if sev not in parser._severity_filter:
                            continue
                        dedup_key = f"{finding.template_id}::{finding.url}::{finding.matched_at}"
                        if dedup_key not in parser._seen_urls:
                            parser._seen_urls.add(dedup_key)
                            parser._findings.append(finding)
                        continue
                    except Exception:
                        pass

                parser.ingest(decoded)
            mm.close()
        return parser
