from __future__ import annotations

import asyncio
import logging
import re
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
            uas = [l.strip() for l in ua_file.read_text().splitlines() if l.strip() and not l.startswith("#")]
            if uas: return uas
        except Exception:
            pass
    return [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ]


class BrowserController:
    """Headless browser worker for stealth scanning, looting, and auth testing."""
    
    DEFAULT_STEALTH_JS = """
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        window.chrome = { runtime: {} };
        Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
        Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
        
        // Mocking hardware concurrency and memory
        Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
        Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });

        const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
        CanvasRenderingContext2D.prototype.getImageData = function(x, y, w, h) {
            const data = originalGetImageData.apply(this, arguments);
            data.data[0] = data.data[0] + (Math.random() > 0.5 ? 1 : -1);
            return data;
        };
    """

    def __init__(self, evasion_level: str = "high", brute_auth: bool = False, tor_mode: bool = False):
        self.evasion_level = evasion_level
        self.brute_auth = brute_auth
        self.tor_mode = tor_mode
        self._browser = None
        self._context = None

    async def start(self, playwright):
        self._browser = await playwright.chromium.launch(headless=True)
        proxy = None
        if self.tor_mode:
            proxy = {"server": "socks5://127.0.0.1:9050"}
            
        import random
        w = random.choice([1920, 1440, 1366])
        h = random.choice([1080, 900, 768])

        self._context = await self._browser.new_context(
            user_agent=_load_user_agents()[random.randint(0, len(_load_user_agents())-1)],
            viewport={'width': w, 'height': h},
            proxy=proxy,
            device_scale_factor=random.choice([1, 2]),
            has_touch=random.choice([True, False])
        )
        if self.evasion_level != "none":
            await self._context.add_init_script(self.DEFAULT_STEALTH_JS)

    async def close(self):
        if self._browser:
            await self._browser.close()

    async def scan_url(self, url: str, token: str | None = None) -> list[dict]:
        findings = []
        page = await self._context.new_page()
        
        page.on("dialog", lambda d: findings.append({
            "type": "vulnerability",
            "id": "dom-xss",
            "name": "DOM-based Cross-Site Scripting",
            "severity": "high",
            "url": url,
            "evidence": d.message
        }))

        try:
            if token:
                domain = url.split("/")[2].split(":")[0]
                await self._context.add_cookies([{"name": "session_token", "value": token, "domain": domain, "path": "/"}])

            fuzz_url = url + ("&" if "?" in url else "?") + "fuzz=<img src=x onerror=alert('DOM_XSS')>"
            await page.goto(fuzz_url, timeout=15000, wait_until="networkidle")

            if token:
                await page.evaluate(f"localStorage.setItem('auth_token', '{token}');")
            
            storage_data = await page.evaluate("""async () => {
                let dbs = [];
                try { if (window.indexedDB && indexedDB.databases) dbs = await indexedDB.databases(); } catch(e) {}
                return {
                    localStorage: JSON.stringify(localStorage),
                    sessionStorage: JSON.stringify(sessionStorage),
                    cookies: document.cookie,
                    indexedDB: JSON.stringify(dbs)
                };
            }""")
            
            if storage_data:
                findings.append({"type": "loot", "url": url, "data": storage_data})

            await page.goto(url + ("&" if "?" in url else "?") + "__proto__[bw_p]=p", timeout=10000, wait_until="networkidle")
            if await page.evaluate("() => window.bw_p === 'p' || {}.bw_p === 'p'"):
                findings.append({
                    "type": "vulnerability",
                    "id": "proto-pollution",
                    "name": "Prototype Pollution",
                    "severity": "medium",
                    "url": url,
                    "evidence": "window.bw_p detected"
                })

            if self.brute_auth and await page.locator("input[type=password]").count() > 0:
                findings.append({
                    "type": "vulnerability",
                    "id": "auth-resilience",
                    "name": "Authentication Resilience",
                    "severity": "info",
                    "url": url,
                    "evidence": "Login form detected; monitored for WAF/lockout resilience."
                })

        except Exception as e:
            logger.debug(f"[Browser] Error {url}: {e}")
        finally:
            await page.close()
            
        return findings


class ScanExecutor:
    """Main orchestrator for hybrid Go/Python security scanning."""

    def __init__(
        self,
        target: str,
        header: str | None = None,
        rps: float | None = None,
        timeout: int | None = None,
        severity: list[str] | None = None,
        dry_run: bool = False,
        evasion_level: str | None = None,
        brute_auth: bool = False,
        action: str = "both",
        tor_mode: bool = False,
        nodes: list[str] | None = None,
    ) -> None:
        cfg = _load_settings()
        self.target = target
        self.header = header
        self.rps = rps or float(cfg["scan"]["default_rps"])
        self.timeout = timeout or cfg["scan"]["timeout_seconds"]
        self.severity = severity or cfg["scan"]["severity_filter"]
        self.dry_run = dry_run
        self.brute_auth = brute_auth
        self.action = action
        self.tor_mode = tor_mode
        self.nodes = nodes or []
        self.job_id = uuid.uuid4().hex[:8]

        oast_cfg = cfg.get("oast", {})
        self._oast_server = OASTServer(
            domain=oast_cfg.get("domain", "oast.local"),
            public_ip=oast_cfg.get("public_ip", "127.0.0.1")
        )
        
        self._mutator = Mutator(oast_domain=oast_cfg.get("domain", "oast.local"))
        self._browser_queue = asyncio.Queue()
        self._results_queue = asyncio.Queue()
        
        self._evasion_level = evasion_level or cfg.get("stealth", {}).get("evasion_level", "high")
        self._browser_workers_count = 3 # Scaling fix

        self._config = cfg
        self._cancelled = False
        self._vulnerabilities = []
        self._pivoted_sessions = set()
        self._current_bridge = None

    async def run(self) -> AsyncIterator[dict]:
        ensure_dir(TMP_DIR / self.job_id)
        logger.info("[%s] Starting scan -> %s", self.job_id, self.target)

        if self.dry_run:
            yield {"type": "dry_run", "job_id": self.job_id, "target": self.target}
            return

        await self._oast_server.start(self._config["oast"]["http_port"], self._config["oast"]["dns_port"])
        
        workers = [asyncio.create_task(self._bridge_worker())]
        if self.action in ("scan", "loot", "both"):
            for _ in range(self._browser_workers_count):
                workers.append(asyncio.create_task(self._browser_worker()))
            
        # OAST polling loop (Loss fix)
        workers.append(asyncio.create_task(self._oast_poller()))

        if self.action == "loot":
            await self._browser_queue.put((self.target, None))

        try:
            while not self._cancelled:
                msg = await self._results_queue.get()
                msg_type = msg.get("type", "")

                if msg_type == "scan_done":
                    if self.action == "loot":
                        await self._browser_queue.join()
                    yield msg
                    break
                
                if msg_type in ("loot", "vulnerability"):
                    evidence = str(msg.get("data", "")) + str(msg.get("evidence", ""))
                    # Generalized token detection fix
                    patterns = [
                        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}", # JWT
                        r"session(?:id)?=([A-Za-z0-9]{20,})", # Generic session cookies
                        r"Bearer\s+([A-Za-z0-9\-\._~+/=]{20,})", # Bearer tokens
                    ]
                    for pattern in patterns:
                        for token in re.findall(pattern, evidence):
                            if token not in self._pivoted_sessions:
                                self._pivoted_sessions.add(token)
                                logger.warning("[PIVOT] New token detected; spawning authenticated context.")
                                yield {
                                    "type": "privilege_escalation",
                                    "subtype": "pivot_spawn",
                                    "token": f"{token[:15]}...",
                                    "source_url": msg.get("url")
                                }
                                await self._browser_queue.put((msg.get("url"), token))

                yield msg
                self._results_queue.task_done()

        except Exception as e:
            logger.error("[%s] Fatal error: %s", self.job_id, e)
            yield {"type": "error", "message": str(e)}
        finally:
            self._current_bridge = None
            for t in workers: t.cancel()
            await self._oast_server.stop()

    async def _oast_poller(self):
        """Periodically check for OAST events independent of bridge messages."""
        last_idx = 0
        while True:
            while last_idx < len(self._oast_server.events):
                ev = self._oast_server.events[last_idx]
                last_idx += 1
                await self._results_queue.put({
                    "type": "oast_hit", "protocol": ev.protocol, 
                    "identifier": ev.identifier, "remote_addr": ev.remote_addr, 
                    "data": ev.data
                })
            await asyncio.sleep(2)

    async def _bridge_worker(self):
        try:
            headers = {}
            if self.header:
                if ":" in self.header:
                    k, v = self.header.split(":", 1)
                    headers[k.strip()] = v.strip()
                else:
                    logger.warning("Invalid header format: %s", self.header)

            async with EngineBridge() as bridge:
                self._current_bridge = bridge
                await bridge.send({
                    "type": "scan_start",
                    "action": self.action,
                    "targets": [self.target],
                    "nodes": self.nodes,
                    "config": {
                        "workers": self._config["engine"]["workers"],
                        "max_depth": self._config["engine"]["max_depth"],
                        "user_agents": _load_user_agents(),
                        "headers": headers,
                        "rps": self.rps,
                        "timeout_seconds": self.timeout,
                        "tor_mode": self.tor_mode,
                        "stealth_mode": self._config["stealth"]["rotate_user_agents"],
                        "jitter": self._config["stealth"]["jitter"],
                        "proxies": self._config["stealth"]["proxies"],
                        "cooldown_seconds": self._config["stealth"]["cooldown_seconds"],
                    },
                })

                async for msg in bridge.stream():
                    if msg.get("type") == "payload_request":
                        import random
                        p = msg.get("param", "")
                        
                        high_priority = []
                        normal_priority = []
                        
                        for cat in ["sqli", "xss", "ssti", "ssrf", "xxe"]:
                            for py in self._mutator.context_aware_payloads(p, cat):
                                payload = py["payload"]
                                if py.get("priority") == "high":
                                    high_priority.append(payload)
                                else:
                                    normal_priority.append(payload)
                        
                        # Dedup and shuffle
                        high_priority = list(set(high_priority))
                        normal_priority = list(set(normal_priority))
                        random.shuffle(high_priority)
                        random.shuffle(normal_priority)
                        
                        # Limit to 15 high-quality payloads total
                        final_payloads = (high_priority + normal_priority)[:15]
                        
                        await bridge.send({"type": "payload_response", "param": p, "payloads": final_payloads})
                    elif msg.get("type") == "node":
                        await self._browser_queue.put((msg.get("url"), None))
                        await self._results_queue.put(msg)
                    else:
                        await self._results_queue.put(msg)
        except Exception as e:
            await self._results_queue.put({"type": "error", "message": f"Bridge: {e}"})

    async def _browser_worker(self):
        try:
            async with async_playwright() as p:
                controller = BrowserController(evasion_level=self._evasion_level, brute_auth=self.brute_auth, tor_mode=self.tor_mode)
                await controller.start(p)
                try:
                    while True:
                        url, token = await self._browser_queue.get()
                        for f in await controller.scan_url(url, token):
                            if f["type"] == "vulnerability": self._vulnerabilities.append(f)
                            await self._results_queue.put(f)
                        self._browser_queue.task_done()
                except asyncio.CancelledError:
                    await asyncio.shield(controller.close())
                except Exception as e:
                    if "EPIPE" not in str(e):
                        logger.error(f"[BrowserWorker] Unexpected error: {e}")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            if "EPIPE" not in str(e):
                logger.error(f"[BrowserWorker] Setup error: {e}")

    async def cancel(self) -> None:
        self._cancelled = True
        if self._current_bridge: await self._current_bridge.close()
