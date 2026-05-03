from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional, List

from src.evidence.manager import EvidenceManager, Artifact, Finding
from src.rules.engine import RulesEngine
from src.models.base import ModelAdapter, DisabledAdapter
from src.browser.controller import BrowserController
from playwright.async_api import async_playwright

logger = logging.getLogger(__name__)

from src.evidence.manager import EvidenceManager, Artifact, Finding, TargetSession
from datetime import datetime

class Orchestrator:
    def __init__(
        self,
        workspace_dir: Path,
        model_adapter: Optional[ModelAdapter] = None
    ):
        self.evidence_mgr = EvidenceManager(workspace_dir / "data" / "evidence")
        self.rules_engine = RulesEngine()
        self.model_adapter = model_adapter or DisabledAdapter()
        self.workspace_dir = workspace_dir
        self.current_session: Optional[TargetSession] = None

    async def run_scan(self, target: str):
        self.current_session = TargetSession(target_url=target)
        self.current_session.pipeline_events.append({"event": "scan_start", "time": datetime.now().isoformat()})
        self.evidence_mgr.save_session(self.current_session)
        
        logger.info(f"Starting deterministic scan on {target}")
        
        try:
            async with async_playwright() as p:
                browser = BrowserController(self.evidence_mgr)
                await browser.start(p)
                
                # 1. Tech Stack Detection (Architecture)
                # In a real scenario, this would probe headers/scripts
                self.current_session.architecture = {"server": "unknown", "frontend": "unknown"}
                
                # 2. Capture baseline
                baseline_id = await browser.navigate_and_capture(target)
                baseline = self.evidence_mgr.get_artifact(baseline_id)
                
                # API Mapping (Extracting endpoints from baseline DOM)
                import re
                urls = re.findall(r'href=[\'"]?([^\'" >]+)', str(baseline.data))
                for url in urls:
                    if url.startswith('/api'):
                        self.current_session.api_map.append({"endpoint": url, "method": "GET"})

                # Apply deterministic rules
                findings = self.rules_engine.analyze(baseline)
                for f in findings:
                    self.evidence_mgr.save_finding(f)
                    logger.info(f"Finding discovered: {f.name} ({f.severity})")

                # Proto pollution test
                pp_id = await browser.test_proto_pollution(target)
                pp_artifact = self.evidence_mgr.get_artifact(pp_id)
                pp_findings = self.rules_engine.analyze(pp_artifact)
                for f in pp_findings:
                    self.evidence_mgr.save_finding(f)
                    logger.info(f"Finding discovered: {f.name} ({f.severity})")

                await browser.close()
                
            self.current_session.status = "success"
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            if self.current_session:
                self.current_session.status = "fail"
                self.current_session.pipeline_events.append({"event": "error", "message": str(e)})
        finally:
            if self.current_session:
                self.current_session.end_time = datetime.now().isoformat()
                self.evidence_mgr.save_session(self.current_session)

    async def run_analyze(self):
        logger.info("Starting AI-assisted analysis layer")
        
        # Initialize and start model adapter if it's an OllamaAdapter or similar
        if hasattr(self.model_adapter, "start"):
            await self.model_adapter.start()

        try:
            findings = self.evidence_mgr.list_findings()
            for f in findings:
                if not f.ai_analysis:
                    # Get relevant artifacts
                    evidence = [self.evidence_mgr.get_artifact(eid) for eid in f.evidence_ids]
                    analysis = await self.model_adapter.classify(evidence)
                    f.ai_analysis = analysis.get("raw")
                    f.confidence = analysis.get("confidence", f.confidence)
                    self.evidence_mgr.save_finding(f)
                    logger.info(f"Analyzed finding {f.id}: {analysis.get('label')}")
        finally:
            if hasattr(self.model_adapter, "stop"):
                await self.model_adapter.stop()

    async def generate_report(self, format: str = "json"):
        findings = self.evidence_mgr.list_findings()
        report_path = self.workspace_dir / "reports" / f"report.{format}"
        
        if format == "json":
            import json
            from dataclasses import asdict
            with open(report_path, "w") as f:
                json.dump([asdict(finding) for finding in findings], f, indent=2)
        
        logger.info(f"Report generated at {report_path}")
        return report_path
