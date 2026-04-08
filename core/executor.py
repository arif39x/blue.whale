from __future__ import annotations

import asyncio
import logging
import os
import signal
import time
import uuid
from pathlib import Path
from typing import AsyncIterator

import yaml

from core.paths import PIPE_SCRIPT, SETTINGS_FILE, TMP_DIR, ensure_dir

logger = logging.getLogger(__name__)


def _load_settings() -> dict:
    with open(SETTINGS_FILE) as f:
        return yaml.safe_load(f)


class WAFDetector:
    # Tracks consecutive 403/429 hits and signals when cooldown should fire.

    def __init__(self, threshold: int, cooldown_seconds: int) -> None:
        self.threshold = threshold
        self.cooldown_seconds = cooldown_seconds
        self._consecutive = 0

    def record_response(self, status_code: int) -> bool:
        # Record a status code. Returns True if cooldown should fire NOW.
        if status_code in (403, 429):
            self._consecutive += 1
            if self._consecutive >= self.threshold:
                self._consecutive = 0
                return True
        else:
            self._consecutive = 0
        return False


class ScanExecutor:
    # Manages the lifecycle of a single scan job.
    # 
    # Usage::
    # 
    #     executor = ScanExecutor(target="https://example.com", rps=10)
    #     async for line in executor.run():
    #         process(line)


    def __init__(
        self,
        target: str,
        rps: int | None = None,
        timeout: int | None = None,
        severity: list[str] | None = None,
        dry_run: bool = False,
    ) -> None:
        cfg = _load_settings()
        self.target = target
        self.rps = rps or cfg["scan"]["default_rps"]
        self.timeout = timeout or cfg["scan"]["timeout_seconds"]
        self.severity = severity or cfg["scan"]["severity_filter"]
        self.dry_run = dry_run
        self.job_id: str = uuid.uuid4().hex[:8]

        stealth_cfg = cfg["stealth"]
        self._waf = WAFDetector(
            threshold=stealth_cfg["cooldown_threshold"],
            cooldown_seconds=stealth_cfg["cooldown_seconds"],
        )
        self._cooldown_seconds: int = stealth_cfg["cooldown_seconds"]

        self._proc: asyncio.subprocess.Process | None = None
        self._cancelled: bool = False

        # Register OS-level signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> AsyncIterator[str]:
        # Async generator that yields raw JSON lines from the scan pipeline.
        # 
        # Lines that contain HTTP status codes will be checked for WAF patterns;
        # cool-down sleeps are injected transparently.

        job_dir = ensure_dir(TMP_DIR / self.job_id)
        logger.info("[%s] Job started → target=%s rps=%s", self.job_id, self.target, self.rps)

        if self.dry_run:
            logger.info("[%s] DRY RUN — skipping subprocess spawn.", self.job_id)
            yield f'{{"type":"dry_run","job_id":"{self.job_id}","target":"{self.target}"}}'
            return

        cmd = [
            "bash",
            str(PIPE_SCRIPT),
            "--target", self.target,
            "--rps", str(self.rps),
            "--timeout", str(self.timeout),
            "--severity", ",".join(self.severity),
            "--job-id", self.job_id,
            "--workdir", str(job_dir),
        ]
        logger.debug("[%s] Spawning: %s", self.job_id, " ".join(cmd))

        try:
            self._proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                # Launch in a new process group so we can kill all children
                start_new_session=True,
            )

            async for line in self._read_stdout():
                if self._cancelled:
                    break
                yield line

            # Drain stderr for diagnostics
            if self._proc.stderr:
                err = await self._proc.stderr.read()
                if err:
                    logger.warning("[%s] stderr: %s", self.job_id, err.decode(errors="replace"))

            await self._proc.wait()
            rc = self._proc.returncode
            logger.info("[%s] Job finished — exit code %s", self.job_id, rc)

        except asyncio.TimeoutError:
            logger.error("[%s] Hard timeout (%ss) exceeded.", self.job_id, self.timeout)
            self.cancel()

    async def cancel(self) -> None:
        # Immediately terminate all child processes.

        self._cancelled = True
        if self._proc and self._proc.returncode is None:
            try:
                pgid = os.getpgid(self._proc.pid)
                os.killpg(pgid, signal.SIGTERM)
                logger.info("[%s] Sent SIGTERM to process group %s", self.job_id, pgid)
                await asyncio.sleep(0.5)
                if self._proc.returncode is None:
                    os.killpg(pgid, signal.SIGKILL)
                    logger.warning("[%s] Escalated to SIGKILL.", self.job_id)
            except ProcessLookupError:
                pass  # process already gone

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _read_stdout(self) -> AsyncIterator[str]:
        # Read stdout line-by-line with timeout guard and WAF detection.

        assert self._proc and self._proc.stdout
        start = time.monotonic()

        try:
            async with asyncio.timeout(self.timeout):
                async for raw in self._proc.stdout:
                    line = raw.decode(errors="replace").rstrip()
                    if not line:
                        continue

                    # Naive WAF detection: look for status codes in JSON output
                    status_code = self._extract_status(line)
                    if status_code and self._waf.record_response(status_code):
                        logger.warning(
                            "[%s] WAF cool-down triggered (%ss pause)",
                            self.job_id, self._cooldown_seconds,
                        )
                        await asyncio.sleep(self._cooldown_seconds)

                    yield line
        except asyncio.TimeoutError:
            raise

    @staticmethod
    def _extract_status(line: str) -> int | None:
        # Return HTTP status code from a JSON line if present, else None.

        import json
        try:
            data = json.loads(line)
            code = data.get("status-code") or data.get("status_code") or data.get("status")
            return int(code) if code else None
        except (json.JSONDecodeError, ValueError, TypeError):
            return None

    def _signal_handler(self, signum: int, frame) -> None:  # noqa: ANN001
        logger.info("Signal %s received — cancelling scan [%s]", signum, self.job_id)
        # Schedule cancel on the running loop if available
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(self.cancel())
            else:
                loop.run_until_complete(self.cancel())
        except RuntimeError:
            pass
