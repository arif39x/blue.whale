class ScanExecutor:
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
            public_ip=oast_cfg.get("public_ip", "127.0.0.1"),
        )

        self._mutator = Mutator(oast_domain=oast_cfg.get("domain", "oast.local"))
        self._jwt_tester = JWTDeepTester(self._mutator)
        self._browser_queue = asyncio.Queue()
        self._results_queue = asyncio.Queue()

        self._evasion_level = evasion_level or cfg.get("stealth", {}).get(
            "evasion_level", "high"
        )
        self._browser_workers_count = 3

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

        await self._oast_server.start(
            self._config["oast"]["http_port"], self._config["oast"]["dns_port"]
        )

        workers = [asyncio.create_task(self._bridge_worker())]
        if self.action in ("scan", "loot", "both"):
            for _ in range(self._browser_workers_count):
                workers.append(asyncio.create_task(self._browser_worker()))

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

                    patterns = [
                        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}",
                        r"session(?:id)?=([A-Za-z0-9]{20,})",
                        r"Bearer\s+([A-Za-z0-9\-\._~+/=]{20,})",
                    ]
                    for pattern in patterns:
                        for token in re.findall(pattern, evidence):
                            if token not in self._pivoted_sessions:
                                self._pivoted_sessions.add(token)
                                logger.warning(
                                    "[PIVOT] New token detected; spawning authenticated context."
                                )
                                yield {
                                    "type": "privilege_escalation",
                                    "subtype": "pivot_spawn",
                                    "token": f"{token[:15]}...",
                                    "source_url": msg.get("url"),
                                }
                                await self._browser_queue.put((msg.get("url"), token))

                yield msg
                self._results_queue.task_done()

        except Exception as e:
            logger.error("[%s] Fatal error: %s", self.job_id, e)
            yield {"type": "error", "message": str(e)}
        finally:
            self._current_bridge = None
            for t in workers:
                t.cancel()
            await self._oast_server.stop()

    async def _oast_poller(self):
        """Periodically check for OAST events independent of bridge messages."""
        last_idx = 0
        while True:
            while last_idx < len(self._oast_server.events):
                ev = self._oast_server.events[last_idx]
                last_idx += 1
                await self._results_queue.put(
                    {
                        "type": "oast_hit",
                        "protocol": ev.protocol,
                        "identifier": ev.identifier,
                        "remote_addr": ev.remote_addr,
                        "data": ev.data,
                    }
                )
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

            llm_cfg = self._config.get("llm", {})
            brain_enabled = llm_cfg.get("enabled", False)

            async with EngineBridge() as bridge:
                self._current_bridge = bridge

                brain = None
                if brain_enabled:
                    try:
                        brain = BrainBridge(
                            ollama_url=llm_cfg.get("ollama_url"),
                            model=llm_cfg.get("preferred_model"),
                            socket_path=TMP_DIR / "brain.sock",
                        )
                        await brain._spawn()
                    except Exception as e:
                        logger.error(f"[bridge] Failed to start brain: {e}")
                        brain = None

                await bridge.send(
                    {
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
                            "stealth_mode": self._config["stealth"][
                                "rotate_user_agents"
                            ],
                            "jitter": self._config["stealth"]["jitter"],
                            "proxies": self._config["stealth"]["proxies"],
                            "cooldown_seconds": self._config["stealth"][
                                "cooldown_seconds"
                            ],
                        },
                    }
                )

                async for msg in bridge.stream():
                    if msg.get("type") == "payload_request":
                        import random

                        p = msg.get("param", "")

                        high_priority = []
                        normal_priority = []

                        for token in self._pivoted_sessions:
                            high_priority.extend(self._jwt_tester.test_token(token))

                        for cat in ["sqli", "xss", "ssti", "ssrf", "xxe"]:
                            if brain:
                                seeds = self._mutator.corpus_mutations(
                                    cat, max_transforms=1
                                )
                                try:
                                    seed = next(seeds)["payload"]
                                    mutations = await brain.mutate(seed, cat, p)
                                    high_priority.extend(mutations)
                                except:
                                    pass

                            for py in self._mutator.context_aware_payloads(p, cat):
                                payload = py["payload"]
                                if py.get("priority") == "high":
                                    high_priority.append(payload)
                                else:
                                    normal_priority.append(payload)

                        high_priority = list(set(high_priority))
                        normal_priority = list(set(normal_priority))
                        random.shuffle(high_priority)
                        random.shuffle(normal_priority)

                        final_payloads = (high_priority + normal_priority)[:15]

                        await bridge.send(
                            {
                                "type": "payload_response",
                                "param": p,
                                "payloads": final_payloads,
                            }
                        )
                    elif msg.get("type") == "feedback":
                        if msg.get("reason") == "WAF_BLOCK":
                            logger.warning(
                                f"[STEALTH] WAF Block detected at {msg.get('url')} (Status: {msg.get('status_code')}). Adjusting mutation strategy."
                            )
                    elif msg.get("type") == "node":
                        await self._browser_queue.put((msg.get("url"), None))
                        await self._results_queue.put(msg)
                    else:
                        await self._results_queue.put(msg)

                if brain:
                    await brain.close()

        except Exception as e:
            await self._results_queue.put({"type": "error", "message": f"Bridge: {e}"})

    async def _browser_worker(self):
        try:
            async with async_playwright() as p:
                controller = BrowserController(
                    evasion_level=self._evasion_level,
                    brute_auth=self.brute_auth,
                    tor_mode=self.tor_mode,
                )
                await controller.start(p)
                try:
                    while True:
                        url, token = await self._browser_queue.get()
                        for f in await controller.scan_url(url, token):
                            if f["type"] == "vulnerability":
                                self._vulnerabilities.append(f)
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
        if self._current_bridge:
            await self._current_bridge.close()
