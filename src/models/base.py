from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class ModelAdapter(ABC):
    @abstractmethod
    async def generate(self, prompt: str, context: Optional[str] = None) -> List[str]:
        pass

    @abstractmethod
    async def classify(self, evidence: Any) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def summarize(self, findings: List[Any]) -> str:
        pass

    @abstractmethod
    async def compare(self, structure_a: Any, structure_b: Any) -> float:
        pass


class DisabledAdapter(ModelAdapter):
    async def generate(self, prompt: str, context: Optional[str] = None) -> List[str]:
        return []

    async def classify(self, evidence: Any) -> Dict[str, Any]:
        return {"label": "unknown", "confidence": 0.0}

    async def summarize(self, findings: List[Any]) -> str:
        return "LLM Analysis Disabled."

    async def compare(self, structure_a: Any, structure_b: Any) -> float:
        return 0.0
