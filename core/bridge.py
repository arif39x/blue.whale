from __future__ import annotations

import asyncio
import logging
import os
import tempfile
from pathlib import Path
from typing import AsyncIterator

import msgpack

from core.paths import ENGINE_BINARY, TMP_DIR

logger = logging.getLogger(__name__)

_DEFAULT_RESTART_DELAY = 1.0
_MAX_RESTARTS = 3
_READ_BUF = 4 * 1024 * 1024


class EngineError(RuntimeError):
    pass


class EngineBridge:
    def __init__(
        self,
        binary: Path | None = None,
        extra_args: list[str] | None = None,
    ) -> None:
        self._binary = binary or ENGINE_BINARY
        self._extra_args = extra_args or []
        self._proc: asyncio.subprocess.Process | None = None
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._server: asyncio.AbstractServer | None = None
        self._socket_path: str | None = None
        self._connected = asyncio.Event()
        self._send_lock = asyncio.Lock()
        self._restarts = 0

    async def __aenter__(self) -> "EngineBridge":
        await self._spawn()
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._connected.set()
        logger.debug("[bridge] Engine connected via UDS")

    async def send(self, msg: dict) -> None:
        if not self._connected.is_set() or self._writer is None:
            await asyncio.wait_for(self._connected.wait(), timeout=10.0)

        packed = msgpack.packb(msg)
        async with self._send_lock:
            try:
                self._writer.write(packed)
                await self._writer.drain()
            except (ConnectionResetError, BrokenPipeError):
                logger.error("[bridge] Failed to send message: connection lost")
                raise EngineError("Engine connection lost")

    async def stream(self) -> AsyncIterator[dict]:
        unpacker = msgpack.Unpacker(raw=False)

        while True:
            if not self._connected.is_set() or self._reader is None:
                try:
                    await asyncio.wait_for(self._connected.wait(), timeout=15.0)
                except asyncio.TimeoutError:
                    if self._proc and self._proc.returncode is not None:
                        break  # process died
                    raise EngineError("Timed out waiting for engine to connect")

            try:
                chunk = await self._reader.read(_READ_BUF)
                if not chunk:
                    await self._wait_for_exit_and_restart()
                    if self._restarts > _MAX_RESTARTS:
                        break
                    continue

                unpacker.feed(chunk)
                for msg in unpacker:
                    yield msg
            except (asyncio.IncompleteReadError, ConnectionResetError):
                await self._wait_for_exit_and_restart()
                if self._restarts > _MAX_RESTARTS:
                    break

    async def _wait_for_exit_and_restart(self) -> None:
        if self._proc is None:
            return

        rc = await self._proc.wait()
        self._connected.clear()

        if rc != 0 and self._restarts < _MAX_RESTARTS:
            logger.warning(
                "[bridge] Engine exited with code %s - restarting (%s/%s)...",
                rc,
                self._restarts + 1,
                _MAX_RESTARTS,
            )
            await asyncio.sleep(_DEFAULT_RESTART_DELAY)
            self._restarts += 1
            await self._spawn()
        else:
            self._proc = None

    async def close(self) -> None:
        self._connected.clear()
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except:
                pass

        if self._server:
            self._server.close()
            await self._server.wait_closed()

        if self._proc:
            try:
                if self._proc.returncode is None:
                    self._proc.terminate()
                    await asyncio.wait_for(self._proc.wait(), timeout=5.0)
            except:
                if self._proc:
                    self._proc.kill()
            self._proc = None

        if self._socket_path and os.path.exists(self._socket_path):
            try:
                os.unlink(self._socket_path)
            except:
                pass

    async def _spawn(self) -> None:
        if not self._binary.exists():
            raise EngineError(f"Engine binary not found at {self._binary}")

        # Ensure TMP_DIR exists
        TMP_DIR.mkdir(parents=True, exist_ok=True)

        fd, path = tempfile.mkstemp(suffix=".sock", dir=str(TMP_DIR))
        os.close(fd)
        os.unlink(path)
        self._socket_path = path

        self._server = await asyncio.start_unix_server(self._handle_client, path)

        cmd = [str(self._binary), "serve", "--socket", path] + self._extra_args
        logger.info("[bridge] Spawning engine: %s", " ".join(cmd))

        self._proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        logger.info("[bridge] Engine PID=%s", self._proc.pid)

        asyncio.create_task(self._drain_stderr())

    async def _drain_stderr(self) -> None:
        if self._proc is None or self._proc.stderr is None:
            return
        async for line in self._proc.stderr:
            decoded = line.decode(errors="replace").rstrip()
            if decoded:
                logger.warning("[engine-stderr] %s", decoded)
