from __future__ import annotations

import re
from typing import Any, List, Optional

from src.evidence.manager import Artifact, Finding


class RulesEngine:
    def __init__(self):
        self.rules = [
            self._rule_dom_xss,
            self._rule_proto_pollution,
        ]

    def analyze(self, artifact: Artifact) -> List[Finding]:
        findings = []
        for rule in self.rules:
            result = rule(artifact)
            if result:
                findings.extend(result)
        return findings

    def _rule_dom_xss(self, artifact: Artifact) -> Optional[List[Finding]]:
        if artifact.type != "dom_snapshot":
            return None

        # look for execution markers in the DOM
        if "DOM_XSS" in str(artifact.data):
            return [
                Finding(
                    name="DOM-based Cross-Site Scripting",
                    category="xss",
                    severity="high",
                    url=artifact.url,
                    evidence_ids=[artifact.id],
                    confidence=1.0,
                    description="Execution marker 'DOM_XSS' found in DOM.",
                )
            ]
        return None

    def _rule_proto_pollution(self, artifact: Artifact) -> Optional[List[Finding]]:
        if artifact.type != "dom_snapshot":
            return None

        if artifact.metadata.get("proto_polluted") is True:
            return [
                Finding(
                    name="Prototype Pollution",
                    category="injection",
                    severity="medium",
                    url=artifact.url,
                    evidence_ids=[artifact.id],
                    confidence=1.0,
                    description="Prototype pollution marker detected in global object.",
                )
            ]
        return None
