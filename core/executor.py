from __future__ import annotations

import asyncio
import logging
import random
import uuid
from typing import AsyncIterator

import yaml
from playwright.async_api import async_playwright

from core.bridge import EngineBridge, EngineError
from core.mutator import Mutator
from core.oast import OASTServer
from core.paths import DATA_DIR, SETTINGS_FILE, TMP_DIR, ensure_dir

logger = logging.getLogger(__name__)


def _load_settings() -> dict:
    with open(SETTINGS_FILE) as f:
        return yaml.safe_load(f)


def _load_user_agents() -> list[str]:
    ua_file = DATA_DIR / "user_agents.txt"
    if ua_file.exists():
        try:
            return [l.strip() for l in ua_file.read_text().splitlines() if l.strip() and not l.startswith("#")]
        except Exception:
            pass
    return [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ]


class ScanExecutor:
    """
    Drives a full scan via the autonomous Go engine bridge.
    Logic (state machine, fuzzing, deduplication) is handled by the Go engine.
    Python handles orchestration, OAST server, and reporting.
    """

    def __init__(
        self,
        target: str,
        header: str | None = None,
        rps: float | None = None,
        timeout: int | None = None,
        severity: list[str] | None = None,
        dry_run: bool = False,
    ) -> None:
        cfg = _load_settings()
        self.target = target
        self.header = header
        self.rps = float(rps) if rps is not None else float(cfg["scan"]["default_rps"])
        self.timeout = timeout or cfg["scan"]["timeout_seconds"]
        self.severity = severity or cfg["scan"]["severity_filter"]
        self.dry_run = dry_run
        self.job_id: str = uuid.uuid4().hex[:8]

        engine_cfg = cfg.get("engine", {})
        self._workers: int = engine_cfg.get("workers", 10)
        self._max_depth: int = engine_cfg.get(
            "max_depth", cfg["scan"].get("max_depth", 3)
        )

        oast_cfg = cfg.get("oast", {})
        oast_domain = oast_cfg.get("domain", "oast.local")
        self._oast_server = OASTServer(
            domain=oast_domain,
            public_ip=oast_cfg.get("public_ip", "127.0.0.1")
        )
        self._oast_http_port = oast_cfg.get("http_port", 80)
        self._oast_dns_port = oast_cfg.get("dns_port", 53)

        self._mutator = Mutator(oast_domain=oast_domain)

        self._browser_queue = asyncio.Queue()

        stealth_cfg = cfg.get("stealth", {})
        self._stealth_mode: bool = stealth_cfg.get("rotate_user_agents", False)
        self._jitter: bool = stealth_cfg.get("jitter", False)
        self._proxies: list[str] = stealth_cfg.get("proxies", [])

        self._cancelled = False
        self._vulnerabilities = []
        self._current_bridge: EngineBridge | None = None

    async def run(self) -> AsyncIterator[dict]:
        ensure_dir(TMP_DIR / self.job_id)
        logger.info(
            "[%s] Autonomous Scan started -> %s", self.job_id, self.target
        )

        if self.dry_run:
            logger.info("[%s] DRY RUN - engine not spawned.", self.job_id)
            yield {"type": "dry_run", "job_id": self.job_id, "target": self.target}
            return

        # Start OAST Server
        await self._oast_server.start(self._oast_http_port, self._oast_dns_port)

        # Start Browser Task
        browser_task = asyncio.create_task(self._browser_scan_task())

        user_agents = _load_user_agents()

        scan_start_msg = {
            "type": "scan_start",
            "targets": [self.target],
            "config": {
                "workers": self._workers,
                "max_depth": self._max_depth,
                "user_agents": user_agents,
                "rps": self.rps,
                "timeout_seconds": self.timeout,
                "stealth_mode": self._stealth_mode,
                "jitter": self._jitter,
                "proxies": self._proxies,
            },
        }

        try:
            async with EngineBridge() as bridge:
                self._current_bridge = bridge
                await bridge.send(scan_start_msg)

                last_oast_event_idx = 0
                async for msg in bridge.stream():
                    if self._cancelled:
                        break

                    # Check for OAST events (currently still polled from Python)
                    while last_oast_event_idx < len(self._oast_server.events):
                        event = self._oast_server.events[last_oast_event_idx]
                        last_oast_event_idx += 1
                        
                        oast_hit = {
                            "type": "oast_hit",
                            "protocol": event.protocol,
                            "identifier": event.identifier,
                            "remote_addr": event.remote_addr,
                            "data": event.data
                        }
                        yield oast_hit

                    msg_type = msg.get("type", "")

                    if msg_type == "payload_request":
                        param = msg.get("param", "")
                        # Generate dynamic payloads for all categories
                        dynamic_payloads = []
                        for cat in ["sqli", "xss", "ssti", "ssrf", "xxe", "idor"]:
                            for p in self._mutator.context_aware_payloads(param, cat):
                                dynamic_payloads.append(p["payload"])
                        
                        # Send back to Go
                        await bridge.send({
                            "type": "payload_response",
                            "param": param,
                            "payloads": list(set(dynamic_payloads))[:50] # Limit to top 50
                        })
                        continue

                    if msg_type == "vulnerability":
                        self._vulnerabilities.append(msg)
                        logger.warning("[%s] FINDING: %s on %s", self.job_id, msg.get("name"), msg.get("url"))
                        yield msg

                    elif msg_type in ("status", "scan_done", "error", "node"):
                        if msg_type == "node":
                            # Queue for DOM XSS check
                            await self._browser_queue.put(msg.get("url"))
                        
                        yield msg
                        if msg_type == "scan_done":
                            await asyncio.sleep(0.5)

                    else:
                        yield msg

        except EngineError as exc:
            logger.error("[%s] Engine error: %s", self.job_id, exc)
            yield {"type": "error", "message": str(exc)}
        finally:
            self._current_bridge = None
            browser_task.cancel()
            await self._oast_server.stop()

        logger.info(
            "[%s] Autonomous Scan complete - %d vulnerabilities found",
            self.job_id,
            len(self._vulnerabilities),
        )

    async def _browser_scan_task(self):
        """Background task that uses Playwright to find DOM XSS and Prototype Pollution."""
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            
            while True:
                url = await self._browser_queue.get()
                try:
                    # 1. Check for DOM XSS
                    page = await context.new_page()
                    page.on("dialog", lambda d: self._on_browser_dialog(d, url))
                    payload = "<img src=x onerror=alert('DOM_XSS')>"
                    target_url = url + ("&" if "?" in url else "?") + "fuzz=" + payload
                    await page.goto(target_url, timeout=10000, wait_until="networkidle")
                    await asyncio.sleep(0.5)
                    await page.close()

                    # 2. Check for Prototype Pollution
                    page = await context.new_page()
                    pp_payload = "__proto__[bw_polluted]=polluted_val"
                    target_url_pp = url + ("&" if "?" in url else "?") + pp_payload
                    await page.goto(target_url_pp, timeout=10000, wait_until="networkidle")
                    
                    is_polluted = await page.evaluate("() => window.bw_polluted === 'polluted_val' || {}.bw_polluted === 'polluted_val'")
                    if is_polluted:
                        finding = {
                            "type": "vulnerability",
                            "id": "proto-pollution",
                            "name": "Client-Side Prototype Pollution",
                            "severity": "medium",
                            "url": url,
                            "param": "__proto__",
                            "payload": pp_payload,
                            "evidence": "window.bw_polluted modified"
                        }
                        self._vulnerabilities.append(finding)
                        logger.warning(f"[PROTO-POLLUTION] FOUND: {url}")
                    
                    await page.close()

                except Exception as e:
                    logger.debug(f"Browser scan error for {url}: {e}")
                finally:
                    self._browser_queue.task_done()

    def _on_browser_dialog(self, dialog, url):
        if "DOM_XSS" in dialog.message:
            finding = {
                "type": "vulnerability",
                "id": "dom-xss",
                "name": "DOM-based Cross-Site Scripting",
                "severity": "high",
                "url": url,
                "param": "DOM",
                "payload": "Playwright detection",
                "evidence": dialog.message
            }
            self._vulnerabilities.append(finding)
            logger.warning(f"[DOM-XSS] FOUND: {url}")
        asyncio.create_task(dialog.dismiss())

    async def cancel(self) -> None:
        self._cancelled = True
        if self._current_bridge:
            await self._current_bridge.close()
