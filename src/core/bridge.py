from __future__ import annotations

import asyncio
import logging
import os
import tempfile
from pathlib import Path
from typing import AsyncIterator

import msgpack

try:
    import pyarrow as pa
    import pyarrow.ipc as ipc
    import grpc
    import core.bridge_pb2 as pb2
    import core.bridge_pb2_grpc as pb2_grpc
except ImportError:
    pass

from core.paths import ENGINE_BINARY, BRAIN_BINARY, TMP_DIR

logger = logging.getLogger(__name__)

_DEFAULT_RESTART_DELAY = 1.0
_MAX_RESTARTS = 3
_READ_BUF = 4 * 1024 * 1024

class EngineError(RuntimeError):
    pass

class GRPCEngineBridge:
    """
    Phase 2 gRPC & Apache Arrow IPC Bridge.
    This class enforces strict typing via Protobuf and utilizes PyArrow for zero-copy
    memory transfers of DOM structures and 'browser loot' between Go/Python/Rust.
    """
    def __init__(self, binary: Path | None = None, socket_path: str | None = None):
        self._binary = binary or ENGINE_BINARY
        self._socket_path = socket_path or str(TMP_DIR / "grpc_engine.sock")
        self._channel = None
        self._stub = None
        self._proc = None

    async def __aenter__(self):

        cmd = [str(self._binary), "serve-grpc", "--socket", self._socket_path]
        logger.info(f"[gRPC Bridge] Spawning engine: {' '.join(cmd)}")
        self._proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        self._channel = grpc.aio.insecure_channel(f"unix://{self._socket_path}")
        self._stub = pb2_grpc.EngineServiceStub(self._channel)
        return self

    async def start_scan(self, config_dict: dict):
        if not self._stub: return

        req = pb2.ScanRequest(
            action=config_dict.get("action", "both"),
            targets=config_dict.get("targets", []),
            config=pb2.ScanConfig(**config_dict.get("config", {}))
        )

        async for event in self._stub.StartScan(req):
            if event.arrow_ipc_handle:

                with pa.memory_map(event.arrow_ipc_handle, 'r') as source:
                    reader = ipc.RecordBatchFileReader(source)
                    table = reader.read_all()
                    event.body = table.to_pydict().get("html", [""])[0]
            yield event

    async def close(self):
        if self._channel:
            await self._channel.close()
        if self._proc:
            try:
                self._proc.terminate()
            except:
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
                        break
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

class BrainBridge:
    def __init__(
        self,
        binary: Path | None = None,
        socket_path: Path | None = None,
        ollama_url: str = "http://localhost:11434",
        model: str | list[str] = "mannix/llama3.1-8b-abliterated:latest",
    ) -> None:
        self._binary = binary or BRAIN_BINARY
        self._socket_path = socket_path or (TMP_DIR / "brain.sock")
        self._ollama_url = ollama_url
        self._model = model
        self._proc: asyncio.subprocess.Process | None = None
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._send_lock = asyncio.Lock()

    async def __aenter__(self) -> "BrainBridge":
        await self._spawn()
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    async def _spawn(self) -> None:
        if not self._binary.exists():
            raise EngineError(f"Brain binary not found at {self._binary}")

        cmd = [
            str(self._binary),
            "--socket", str(self._socket_path),
            "--ollama-url", self._ollama_url,
        ]

        models = self._model
        if isinstance(models, str):
            models = [m.strip() for m in models.split(",")]

        for m in models:
            cmd.extend(["--models", m])

        logger.info("[bridge] Spawning brain: %s", " ".join(cmd))

        self._proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        for _ in range(30):
            if self._socket_path.exists():
                try:
                    self._reader, self._writer = await asyncio.open_unix_connection(str(self._socket_path))
                    logger.info("[bridge] Connected to brain via UDS")
                    return
                except:
                    pass
            await asyncio.sleep(0.2)

        raise EngineError("Brain failed to start or socket timed out")

    async def mutate(self, payload: str, category: str, context: str) -> list[str]:
        if not self._writer:
            return []

        msg = {
            "type": "mutate",
            "payload": payload,
            "category": category,
            "context": context,
        }

        async with self._send_lock:
            packed = msgpack.packb(msg)
            self._writer.write(packed)
            await self._writer.drain()

            unpacker = msgpack.Unpacker(raw=False)
            while True:
                chunk = await self._reader.read(8192)
                if not chunk:
                    break
                unpacker.feed(chunk)
                for resp in unpacker:
                    if resp.get("type") == "mutation_results":
                        return resp.get("results", [])
                    return []
        return []

    async def analyze(self, evidence: str, category: str) -> str:
        if not self._writer:
            return "Brain not connected"

        msg = {
            "type": "analyze",
            "payload": evidence,
            "category": category,
        }

        async with self._send_lock:
            packed = msgpack.packb(msg)
            self._writer.write(packed)
            await self._writer.drain()

            unpacker = msgpack.Unpacker(raw=False)
            while True:
                chunk = await self._reader.read(8192)
                if not chunk:
                    break
                unpacker.feed(chunk)
                for resp in unpacker:
                    if resp.get("type") == "analysis_results":
                        return resp.get("analysis", "No analysis provided")
                    return "Unexpected response type"
        return "No response from brain"

    async def close(self) -> None:
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except:
                pass

        if self._proc:
            try:
                self._proc.terminate()
                await self._proc.wait()
            except:
                pass
            self._proc = None

        if self._socket_path.exists():
            try:
                self._socket_path.unlink()
            except:
                pass
