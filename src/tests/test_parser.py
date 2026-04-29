# tests/test_parser.py - Unit tests for core/parser.py.
# 
# Tests run without any external binaries; they only exercise the Python
# validation, de-duplication, and export logic.

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from core.parser import Finding, ResultParser, Severity


# ---------------------------------------------------------------------------
# Sample payloads (mimicking Nuclei JSON output)
# ---------------------------------------------------------------------------

NUCLEI_FINDING_CRITICAL = {
    "template-id": "CVE-2021-44228",
    "info": {"name": "Log4Shell RCE", "severity": "critical"},
    "host": "https://example.com",
    "matched-at": "https://example.com/log4j",
    "status-code": 200,
    "timestamp": "2024-01-01T00:00:00Z",
}

NUCLEI_FINDING_HIGH = {
    "template-id": "sqli-generic",
    "info": {"name": "SQL Injection", "severity": "high"},
    "host": "https://example.com",
    "matched-at": "https://example.com/search?q=1",
    "status-code": 500,
    "timestamp": "2024-01-01T00:00:01Z",
}

NUCLEI_FINDING_INFO = {
    "template-id": "tech-detect-nginx",
    "info": {"name": "Nginx Detected", "severity": "info"},
    "host": "https://example.com",
    "matched-at": "https://example.com/",
    "status-code": 200,
    "timestamp": "2024-01-01T00:00:02Z",
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestResultParser:

    def test_ingest_valid_finding(self):
        parser = ResultParser()
        line = json.dumps(NUCLEI_FINDING_CRITICAL)
        finding = parser.ingest(line)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert finding.name == "Log4Shell RCE"
        assert finding.template_id == "CVE-2021-44228"

    def test_ingest_invalid_json_returns_none(self):
        parser = ResultParser()
        result = parser.ingest("not json at all <<<")
        assert result is None

    def test_ingest_deduplication(self):
        parser = ResultParser()
        line = json.dumps(NUCLEI_FINDING_CRITICAL)
        f1 = parser.ingest(line)
        f2 = parser.ingest(line)  # exact duplicate
        assert f1 is not None
        assert f2 is None  # de-duplicated
        assert len(parser.sorted_findings()) == 1

    def test_severity_filter_excludes_below_threshold(self):
        parser = ResultParser(severity_filter=["critical", "high"])
        assert parser.ingest(json.dumps(NUCLEI_FINDING_CRITICAL)) is not None
        assert parser.ingest(json.dumps(NUCLEI_FINDING_HIGH)) is not None
        assert parser.ingest(json.dumps(NUCLEI_FINDING_INFO)) is None  # filtered

    def test_sorted_findings_critical_first(self):
        parser = ResultParser()
        parser.ingest(json.dumps(NUCLEI_FINDING_INFO))
        parser.ingest(json.dumps(NUCLEI_FINDING_CRITICAL))
        parser.ingest(json.dumps(NUCLEI_FINDING_HIGH))
        findings = parser.sorted_findings()
        assert findings[0].severity == Severity.CRITICAL
        assert findings[1].severity == Severity.HIGH
        assert findings[2].severity == Severity.INFO

    def test_stats_counts(self):
        parser = ResultParser()
        parser.ingest(json.dumps(NUCLEI_FINDING_CRITICAL))
        parser.ingest(json.dumps(NUCLEI_FINDING_HIGH))
        parser.ingest(json.dumps(NUCLEI_FINDING_INFO))
        stats = parser.stats
        assert stats["critical"] == 1
        assert stats["high"] == 1
        assert stats["info"] == 1

    def test_export_jsonl_roundtrip(self):
        parser = ResultParser()
        parser.ingest(json.dumps(NUCLEI_FINDING_CRITICAL))
        parser.ingest(json.dumps(NUCLEI_FINDING_HIGH))

        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "results.jsonl"
            parser.export_jsonl(out_path)
            assert out_path.exists()
            lines = out_path.read_text().strip().splitlines()
            assert len(lines) == 2
            for line in lines:
                data = json.loads(line)
                assert "template_id" in data
                assert "severity" in data

    def test_export_csv_headers(self):
        parser = ResultParser()
        parser.ingest(json.dumps(NUCLEI_FINDING_CRITICAL))

        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "results.csv"
            parser.export_csv(out_path)
            assert out_path.exists()
            header = out_path.read_text().splitlines()[0]
            assert "severity" in header
            assert "url" in header

    def test_from_file_mmap(self):
        # ResultParser.from_file should reload findings from a JSONL file.

        parser = ResultParser()
        parser.ingest(json.dumps(NUCLEI_FINDING_CRITICAL))
        parser.ingest(json.dumps(NUCLEI_FINDING_HIGH))

        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "results.jsonl"
            parser.export_jsonl(out_path)

            reloaded = ResultParser.from_file(out_path)
            assert len(reloaded.sorted_findings()) == 2


class TestFinding:

    def test_severity_normalised_to_lowercase(self):
        f = Finding(**{
            "template-id": "test-id",
            "name": "Test Finding",
            "severity": "CRITICAL",
            "url": "https://example.com",
        })
        assert f.severity == Severity.CRITICAL

    def test_unknown_severity_fallback(self):
        f = Finding(**{
            "template-id": "test-id",
            "name": "Test Finding",
            "severity": "gibberish",
            "url": "https://example.com",
        })
        assert f.severity == Severity.UNKNOWN

    def test_to_dict_is_serialisable(self):
        f = Finding(**{
            "template-id": "test-id",
            "name": "Test",
            "severity": "low",
            "url": "https://example.com",
        })
        d = f.to_dict()
        assert json.dumps(d)  # must be JSON serialisable
