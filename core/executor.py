from __future__ import annotations

import asyncio
import logging
import random
import signal
import time
import uuid
from pathlib import Path
from typing import AsyncIterator

import yaml

from core.bridge import EngineBridge, EngineError
from core.paths import DATA_DIR, SETTINGS_FILE, TMP_DIR, ensure_dir
from core.state_machine import StateMachine
from core.waf import WAFFingerprinter

logger = logging.getLogger(__name__)


def _load_settings() -> dict:
    with open(SETTINGS_FILE) as f:
        return yaml.safe_load(f)


def _get_random_ua() -> str:
    ua_file = DATA_DIR / "user_agents.txt"
    fallback = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
    if ua_file.exists():
        try:
            agents = [l.strip() for l in ua_file.read_text().splitlines() if l.strip()]
            if agents:
                return random.choice(agents)
        except Exception:
            pass
    return fallback


class WAFCooldown:
    # Tracks consecutive 403/429 hits and signals cooldown.

    def __init__(self, threshold: int, cooldown_seconds: int) -> None:
        self.threshold = threshold
        self.cooldown_seconds = cooldown_seconds
        self._consecutive = 0

    def record(self, status: int) -> bool:
        # Returns True if cooldown should fire NOW.
        if status in (403, 429):
            self._consecutive += 1
            if self._consecutive >= self.threshold:
                self._consecutive = 0
                return True
        else:
            self._consecutive = 0
        return False


class ScanExecutor:
    # Drives a full scan via the native Go engine bridge.

    def __init__(
        self,
        target: str,
        header: str | None = None,
        rps: int | None = None,
        timeout: int | None = None,
        severity: list[str] | None = None,
        dry_run: bool = False,
    ) -> None:
        cfg = _load_settings()
        self.target = target
        self.header = header
        self.rps = rps or cfg["scan"]["default_rps"]
        self.timeout = timeout or cfg["scan"]["timeout_seconds"]
        self.severity = severity or cfg["scan"]["severity_filter"]
        self.dry_run = dry_run
        self.job_id: str = uuid.uuid4().hex[:8]

        engine_cfg = cfg.get("engine", {})
        self._workers: int = engine_cfg.get("workers", 10)
        self._max_depth: int = engine_cfg.get(
            "max_depth", cfg["scan"].get("max_depth", 3)
        )

        stealth_cfg = cfg["stealth"]
        self._waf_cooldown = WAFCooldown(
            threshold=stealth_cfg["cooldown_threshold"],
            cooldown_seconds=stealth_cfg["cooldown_seconds"],
        )
        self._cooldown_seconds: int = stealth_cfg["cooldown_seconds"]
        self._rotate_ua: bool = stealth_cfg.get("rotate_user_agents", True)

        self._state_machine = StateMachine()
        self._waf_fp = WAFFingerprinter()
        self._detected_waf: str | None = None
        self._cancelled = False
        self._paused = False  # WAF cooldown pause flag - prevents blocking IPC stream

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    async def run(self) -> AsyncIterator[dict]:

        ensure_dir(TMP_DIR / self.job_id)
        logger.info(
            "[%s] Scan started -> %s  rps=%s", self.job_id, self.target, self.rps
        )

        if self.dry_run:
            logger.info("[%s] DRY RUN - engine not spawned.", self.job_id)
            yield {"type": "dry_run", "job_id": self.job_id, "target": self.target}
            return

        ua = _get_random_ua() if self._rotate_ua else _get_random_ua()

        scan_start_msg = {
            "type": "scan_start",
            "targets": [self.target],
            "config": {
                "workers": self._workers,
                "max_depth": self._max_depth,
                "ua": ua,
                "rps": self.rps,
                "timeout_seconds": self.timeout,
            },
        }

        try:
            async with EngineBridge() as bridge:
                await bridge.send(scan_start_msg)

                # Pending fuzz jobs we still need to send
                pending_jobs: asyncio.Queue[dict] = asyncio.Queue()

                async def _fuzz_sender():
                    while not self._cancelled:
                        # WAF Cooldown: pause sending new fuzz jobs but don't block IPC
                        if self._paused:
                            await asyncio.sleep(1)
                            continue
                        try:
                            job = await asyncio.wait_for(
                                pending_jobs.get(), timeout=1.0
                            )
                            await bridge.send(job)
                        except asyncio.TimeoutError:
                            continue

                sender_task = asyncio.create_task(_fuzz_sender())

                async for msg in bridge.stream():
                    if self._cancelled:
                        break

                    msg_type = msg.get("type", "")

                    if msg_type == "node":
                        # Generate follow-up fuzz jobs from state machine
                        fuzz_jobs = self._state_machine.process_node(msg)
                        for job in fuzz_jobs:
                            await pending_jobs.put(job.to_dict())
                        yield msg

                    elif msg_type == "fuzz_result":
                        status = msg.get("status", 0)
                        # WAF cooldown - NON-BLOCKING: uses async background task
                        # This allows the IPC stream to continue reading from Go engine
                        # while pausing new fuzz job sends (prevents OS pipe buffer overflow)
                        if self._waf_cooldown.record(status) and not self._paused:
                            logger.warning(
                                "[%s] WAF cooldown triggered - pausing sends %ss",
                                self.job_id,
                                self._cooldown_seconds,
                            )

                            async def _cooldown_task():
                                """Async background task for WAF cooldown.
                                Sets paused flag, sleeps, then clears it.
                                Does NOT block the main IPC stream."""
                                self._paused = True
                                await asyncio.sleep(self._cooldown_seconds)
                                self._paused = False
                                logger.info(
                                    "[%s] WAF cooldown complete - resuming sends",
                                    self.job_id,
                                )

                            # Fire-and-forget: don't await, let it run concurrently
                            asyncio.create_task(_cooldown_task())

                        # State machine follow-up
                        follow_ups = self._state_machine.process_result(msg)
                        for job in follow_ups:
                            if job.url:  # only queue if URL is known
                                await pending_jobs.put(job.to_dict())
                        yield msg

                    elif msg_type in ("status", "scan_done", "error", "dry_run"):
                        yield msg
                        if msg_type == "scan_done":
                            await asyncio.sleep(0.5)

                    else:
                        yield msg

                sender_task.cancel()

        except EngineError as exc:
            logger.error("[%s] Engine error: %s", self.job_id, exc)
            yield {"type": "error", "message": str(exc)}

        logger.info(
            "[%s] Scan complete - %d endpoints discovered",
            self.job_id,
            self._state_machine.endpoint_count,
        )

    async def cancel(self) -> None:
        self._cancelled = True

    def _signal_handler(self, signum: int, frame) -> None:
        logger.info("Signal %s - cancelling scan [%s]", signum, self.job_id)
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(self.cancel())
            else:
                loop.run_until_complete(self.cancel())
        except RuntimeError:
            pass
