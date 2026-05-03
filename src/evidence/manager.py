from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Artifact:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    type: str = "raw_http"  # raw_http, dom_snapshot, storage_dump, screenshot, oast_callback, target_metadata
    url: str = ""
    data: Any = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    category: str = ""
    severity: str = "info"  # critical, high, medium, low, info
    description: str = ""
    url: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.0
    ai_analysis: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TargetSession:
    """Stores full target context, architecture, and pipeline status."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_url: str = ""
    status: str = "pending" # success, fail, partial
    architecture: Dict[str, Any] = field(default_factory=dict) # detected tech stack
    api_map: List[Dict[str, Any]] = field(default_factory=list) # endpoints discovered
    pipeline_events: List[Dict[str, Any]] = field(default_factory=list)
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: Optional[str] = None


class EvidenceManager:
    def __init__(self, storage_dir: Path):
        self.storage_dir = storage_dir
        self.artifacts_dir = storage_dir / "artifacts"
        self.findings_dir = storage_dir / "findings"
        self.sessions_dir = storage_dir / "sessions"
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.findings_dir.mkdir(parents=True, exist_ok=True)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)

    def save_artifact(self, artifact: Artifact) -> str:
        path = self.artifacts_dir / f"{artifact.id}.json"
        with open(path, "w") as f:
            json.dump(asdict(artifact), f, indent=2)
        return artifact.id

    def save_finding(self, finding: Finding) -> str:
        path = self.findings_dir / f"{finding.id}.json"
        with open(path, "w") as f:
            json.dump(asdict(finding), f, indent=2)
        return finding.id
    
    def save_session(self, session: TargetSession) -> str:
        path = self.sessions_dir / f"{session.id}.json"
        with open(path, "w") as f:
            json.dump(asdict(session), f, indent=2)
        return session.id

    def get_artifact(self, artifact_id: str) -> Optional[Artifact]:
        path = self.artifacts_dir / f"{artifact_id}.json"
        if not path.exists():
            return None
        with open(path, "r") as f:
            data = json.load(f)
            return Artifact(**data)

    def get_session(self, session_id: str) -> Optional[TargetSession]:
        path = self.sessions_dir / f"{session_id}.json"
        if not path.exists(): return None
        with open(path, "r") as f:
            return TargetSession(**json.load(f))

    def list_findings(self) -> List[Finding]:
        findings = []
        for path in self.findings_dir.glob("*.json"):
            with open(path, "r") as f:
                data = json.load(f)
                findings.append(Finding(**data))
        return findings
