Blue Whale

Blue Whale is a hybrid vulnerability scanner designed for two things: insane speed and WAF evasion.

1. The Split-Brain Design
   We use a dual-component architecture communicating over Unix Domain Sockets (UDS) using Msgpack.

- The Orchestrator (Python 3.12+): This is the brain. It handles the high-level logic: crawl management, template parsing, OAST (Out-of-Band) polling, and headless browser automation (Playwright). Python
  gives us access to a massive ecosystem for data processing and browser control.
- The Engine (Go 1.26+): This is the muscle. It handles raw network I/O. We don't use Go’s standard http.Client because it's too "polite" and easily fingerprinted. Instead, the Go engine builds raw
  HTTP/1.1 requests from scratch to allow for things like Request Smuggling and precise header manipulation.

2. The Bridge (IPC)
   Instead of a slow REST API, the two components talk via a binary stream over a local socket.

- Protocol: Msgpack (Binary JSON).
- Flow: Python sends a scan_start message with a config. Go starts the crawl and streams node (discovered URLs) and vulnerability messages back in real-time. If the engine needs more payloads for a
  specific parameter, it sends a payload_request to Python and waits for the response.

3. The Go Execution Engine
   This is where the heavy lifting happens. To bypass modern WAFs (like Sucuri or Cloudflare), we implemented:

- Raw Dialing: We open TCP/TLS connections manually.
- uTLS (JA3 Fingerprinting): We spoof the TLS Hello packets of real browsers (Chrome/Firefox) so the WAF thinks we are a human, not a Go script.
- ALPN Stripping: We forcefully strip h2 from the TLS handshake to force the server into http/1.1. This is critical for our raw request parser and for testing vulnerabilities like Request Smuggling.
- Defense Evasion: Every request gets a randomized, realistic User-Agent and Accept header.

4. Hybrid Scanning Logic
   We use a multi-layered approach to finding bugs:
1. Passive Fingerprinting: As we crawl, we identify the tech stack (headers, bodies).
1. Differential Analysis: We compare a "baseline" response with a fuzzed response. If the status code or page size changes significantly (and it’s not a 404), we flag it.
1. Headless Looting: For every discovered page, a background Python worker spawns a Playwright instance to look for DOM-XSS, sensitive data in localStorage, and Prototype Pollution.
1. OAST Interaction: We inject unique hostnames pointing to our OAST server. If the target server makes a DNS or HTTP request back to us, we catch it and link it to the specific payload.

1. Security & Stability

- SSRF Protection: The engine has a built-in blacklist for private IP ranges (10.0.0.0/8, etc.) and sensitive ports (22, 3306, 6379) to prevent the scanner from being used as a pivot into an internal
  network.
- Concurrency Control: We use a custom HostRateLimiter with jitter. If a WAF starts returning 403s or 429s, the engine automatically "cools down" that specific host for 30 seconds without stopping the rest
  of the scan.

6. Data Flow Summary
1. CLI takes user input -> Python Orchestrator.
1. Python spawns Go Engine and opens the socket.
1. Go crawls the target at high speed using raw sockets.
1. Go finds a parameter -> asks Python for context-aware payloads.
1. Go executes payloads -> streams results back.
1. Python (Parallel) runs Playwright on discovered links for client-side bugs.
1. Python aggregates everything into a final JSONL/PDF report.
