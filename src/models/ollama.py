from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

from src.core.bridge import BrainBridge
from src.models.base import ModelAdapter

logger = logging.getLogger(__name__)


class OllamaAdapter(ModelAdapter):
    # Keywords used to identify models suitable for offensive security (bypass filters)
    SECURITY_KEYWORDS = [
        "abliterate",
        "dolphin",
        "uncensored",
        "hermes",
        "instruct",
        "vicuna",
        "llama3",
    ]

    def __init__(
        self, ollama_url: str, socket_path: Any, models: Optional[List[str]] = None
    ):
        self.ollama_url = ollama_url
        self.socket_path = socket_path
        self.detected_models = models or []
        self.bridge: Optional[BrainBridge] = None

    async def _detect_local_models(self) -> List[str]:
        """Detect models currently available in Ollama."""
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{self.ollama_url}/api/tags", timeout=5.0)
                if resp.status_code == 200:
                    data = resp.json()
                    return [m["name"] for m in data.get("models", [])]
        except Exception as e:
            logger.warning(f"[Ollama] Failed to detect models: {e}")
        return []

    async def _recommend_models(self):
        """Guide the user on how to find and pull suitable uncensored models."""
        print("\n[bold yellow][!][/bold yellow] No models detected in Ollama.")
        print("BlueWhale requires an LLM for AI-augmented features.")
        print(
            "For security testing, it is recommended to use [bold]uncensored[/bold] or [bold]abliterated[/bold] models."
        )
        print("\n[bold]Recommendation:[/bold]")
        print(
            "1. Visit [link=https://ollama.com/library]ollama.com/library[/link] and search for 'uncensored' or 'abliterated'."
        )
        print("2. Pull a model using: [cyan]ollama pull <model_name>[/cyan]")
        print(
            f"   (Common keywords to look for: {', '.join(self.SECURITY_KEYWORDS[:4])})"
        )
        print("")

    async def start(self):
        if not self.detected_models:
            self.detected_models = await self._detect_local_models()

        if not self.detected_models:
            await self._recommend_models()
        else:
            prioritized = [
                m
                for m in self.detected_models
                if any(k in m.lower() for k in self.SECURITY_KEYWORDS)
            ]
            if prioritized:
                logger.info(
                    f"[Ollama] Prioritizing security-aligned models: {prioritized}"
                )
                self.detected_models = prioritized + [
                    m for m in self.detected_models if m not in prioritized
                ]
            else:
                logger.info(f"[Ollama] Using detected models: {self.detected_models}")

        self.bridge = BrainBridge(
            ollama_url=self.ollama_url,
            model=self.detected_models,
            socket_path=self.socket_path,
        )
        await self.bridge._spawn()

    async def stop(self):
        if self.bridge:
            await self.bridge.close()

    async def generate(self, prompt: str, context: Optional[str] = None) -> List[str]:
        if not self.bridge:
            return []
        return await self.bridge.mutate(prompt, "general", context or "")

    async def classify(self, evidence: Any) -> Dict[str, Any]:
        if not self.bridge:
            return {"label": "error", "confidence": 0.0}
        analysis = await self.bridge.analyze(str(evidence), "general")

        confidence = 0.5
        label = "candidate"
        if "true positive" in analysis.lower():
            confidence = 0.9
            label = "vulnerability"
        elif "false positive" in analysis.lower():
            confidence = 0.9
            label = "false_positive"

        return {"label": label, "confidence": confidence, "raw": analysis}

    async def summarize(self, findings: List[Any]) -> str:
        if not self.bridge:
            return "LLM not available."
        return "AI Summary: " + ", ".join([f.name for f in findings])

    async def compare(self, structure_a: Any, structure_b: Any) -> float:
        if not self.bridge:
            return 0.0
        analysis = await self.bridge.analyze(
            f"Compare structure A: {structure_a} and B: {structure_b}", "comparison"
        )
        if "identical" in analysis.lower():
            return 1.0
        return 0.5
