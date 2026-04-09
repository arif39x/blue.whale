from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import AsyncIterator

from core.paths import ENGINE_BINARY

logger = logging.getLogger(__name__)

_DEFAULT_RESTART_DELAY = 2.0  # seconds before restart on crash
_MAX_RESTARTS = 3
_READ_BUF = 2 * 1024 * 1024  # 2 MB read buffer


class EngineError(RuntimeError):
    pass


class EngineBridge:
    # Async context manager that owns the Go engine subprocess.
    # Provides send() for writing commands and stream() for reading events.

    def __init__(
        self,
        binary: Path | None = None,
        extra_args: list[str] | None = None,
    ) -> None:
        self._binary = binary or ENGINE_BINARY
        self._extra_args = extra_args or []
        self._proc: asyncio.subprocess.Process | None = None
        self._send_lock = asyncio.Lock()
        self._restarts = 0

    async def __aenter__(self) -> "EngineBridge":
        await self._spawn()
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    async def send(self, msg: dict) -> None:
        # Write a single JSON-RPC message to the engine stdin.

        if self._proc is None or self._proc.stdin is None:
            raise EngineError("Engine is not running.")
        line = json.dumps(msg, separators=(",", ":")) + "\n"
        async with self._send_lock:
            self._proc.stdin.write(line.encode())
            await self._proc.stdin.drain()
        logger.debug("[bridge] -> %s", line.rstrip())

    async def stream(self) -> AsyncIterator[dict]:
        # Async generator that yields parsed JSON dicts from engine stdout.
        # Automatically restarts the engine on premature exit (up to _MAX_RESTARTS).

        while True:
            if self._proc is None or self._proc.stdout is None:
                raise EngineError("Engine is not running.")

            stdout = self._proc.stdout
            try:
                async for raw in stdout:
                    line = raw.decode(errors="replace").strip()
                    if not line:
                        continue
                    try:
                        msg = json.loads(line)
                    except json.JSONDecodeError:
                        logger.debug("[bridge] Non-JSON from engine: %s", line[:200])
                        continue
                    logger.debug("[bridge] <- %s", line[:200])
                    yield msg
            except (asyncio.IncompleteReadError, ConnectionResetError):
                pass  # engine closed stdout

            # Engine stdout ended - check if it crashed
            rc = await self._proc.wait()
            if rc != 0 and self._restarts < _MAX_RESTARTS:
                logger.warning(
                    "[bridge] Engine exited with code %s - restarting (%s/%s)...",
                    rc,
                    self._restarts + 1,
                    _MAX_RESTARTS,
                )
                await asyncio.sleep(_DEFAULT_RESTART_DELAY)
                await self._spawn()
                self._restarts += 1
            else:
                # Clean exit or too many restarts
                break

    async def close(self) -> None:
        # Gracefully terminate the engine subprocess.

        if self._proc is None:
            return
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
            if self._proc.returncode is None:
                self._proc.terminate()
                try:
                    await asyncio.wait_for(self._proc.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    self._proc.kill()
                    await self._proc.wait()
        except ProcessLookupError:
            pass
        finally:
            logger.debug("[bridge] Engine process closed.")
            self._proc = None

    async def _spawn(self) -> None:
        if not self._binary.exists():
            raise EngineError(
                f"whale-engine binary not found at {self._binary}. "
                "Run 'python main.py bootstrap' to build it."
            )
        cmd = [str(self._binary), "serve"] + self._extra_args
        logger.info("[bridge] Spawning engine: %s", " ".join(cmd))
        self._proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=_READ_BUF,
        )
        logger.info("[bridge] Engine PID=%s", self._proc.pid)

        # Drain stderr in background so it doesn't block the pipe
        asyncio.create_task(self._drain_stderr())

    async def _drain_stderr(self) -> None:
        if self._proc is None or self._proc.stderr is None:
            return
        async for line in self._proc.stderr:
            decoded = line.decode(errors="replace").rstrip()
            if decoded:
                logger.debug("[engine-stderr] %s", decoded)
