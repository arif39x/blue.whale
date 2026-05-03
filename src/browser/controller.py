from __future__ import annotations

import logging
import random
from typing import Optional, List
from playwright.async_api import async_playwright, Playwright
from src.evidence.manager import EvidenceManager, Artifact

logger = logging.getLogger(__name__)

class BrowserController:
    DEFAULT_STEALTH_JS = """
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        window.chrome = { runtime: {} };
        Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
        Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
        Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
        Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
    """

    def __init__(self, evidence_mgr: EvidenceManager, tor_mode: bool = False):
        self.evidence_mgr = evidence_mgr
        self.tor_mode = tor_mode
        self._browser = None
        self._context = None

    async def start(self, playwright: Playwright):
        self._browser = await playwright.chromium.launch(headless=True)
        proxy = {"server": "socks5://127.0.0.1:9050"} if self.tor_mode else None
        
        self._context = await self._browser.new_context(
            viewport={"width": 1920, "height": 1080},
            proxy=proxy
        )
        await self._context.add_init_script(self.DEFAULT_STEALTH_JS)

    async def close(self):
        if self._browser:
            await self._browser.close()

    async def navigate_and_capture(self, url: str) -> str:
        """Navigates to URL, captures DOM and storage, saves as artifact."""
        page = await self._context.new_page()
        try:
            await page.goto(url, timeout=30000, wait_until="networkidle")
            
            dom = await page.content()
            storage = await page.evaluate("""() => ({
                localStorage: JSON.stringify(localStorage),
                sessionStorage: JSON.stringify(sessionStorage),
                cookies: document.cookie
            })""")
            
            artifact = Artifact(
                type="dom_snapshot",
                url=url,
                data=dom,
                metadata={"storage": storage}
            )
            return self.evidence_mgr.save_artifact(artifact)
        finally:
            await page.close()

    async def test_proto_pollution(self, url: str) -> str:
        page = await self._context.new_page()
        try:
            test_url = url + ("&" if "?" in url else "?") + "__proto__[bw_p]=p"
            await page.goto(test_url, timeout=15000, wait_until="networkidle")
            polluted = await page.evaluate("() => window.bw_p === 'p' || {}.bw_p === 'p'")
            
            dom = await page.content()
            artifact = Artifact(
                type="dom_snapshot",
                url=url,
                data=dom,
                metadata={"proto_polluted": polluted}
            )
            return self.evidence_mgr.save_artifact(artifact)
        finally:
            await page.close()
