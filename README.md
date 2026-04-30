# Project BlueWhale

![Blue Whale Logo](assets/Logo.png)

**BlueWhale** is an advanced, high-fidelity vulnerability orchestration platform engineered for offensive-defensive auditing. It employs a **Kinetic-Cognitive-Orchestral** triple-core model, synchronizing a high-performance Go network engine with a Rust-based LLM orchestrator and a Python-based SLM for semantic intent analysis and polymorphic execution.

---

## Core Philosophy
> "Security is a temporary state of resistance. Nothing is absolute. There must be a vulnerability; BlueWhale will find it."

---

## High-Fidelity Features

- **Kinetic-Cognitive-Orchestral Model:** 
  - **Kinetic Core (Go):** High-speed network engine with custom TCP/TLS stacks.
  - **Orchestral Layer (Rust):** High-performance multi-model LLM management for parallel mutation and analysis.
  - **Cognitive Core (Python):** Small Language Model (SLM) for intent analysis and complex logic testing.
- **Defensive Neutralization Matrix:**
  - **Adaptive Pacing (PID Controller):** Network-aware rate limiting that dynamically adjusts RPS based on target latency (TTFB) to evade detection.
  - **Adversarial Noise Injection:** Randomly interspersed non-malicious requests (Favicon, CSS, JS) to flatten WAF anomaly scores.
  - **TLS Fingerprinting:** Dynamic JA3/JA4 spoofing using `uTLS` to mimic legitimate browser stacks (Chrome, Firefox, Safari).
- **Semantic Verification (Anti-False Positive):**
  - **DOM-Tree Hashing:** Eliminates false positives by comparing SHA-256 hashes of structural nodes, ignoring dynamic content.
  - **SLM Verification Gate:** Automated AI-driven "Proof of Concept" (PoC) verification for all discovered vulnerabilities.
- **"Ghost" Session Orchestration:** 
  - **Multi-Identity Testing:** Concurrent scanning using a `SessionMap` to automatically test for IDOR and BFLA by swapping headers (Admin, User, Guest) on the fly.
- **Recursive Headless Discovery:** Playwright-integrated SPA crawling to identify hidden API endpoints and DOM-based XSS.
- **Out-of-Band (OAST) Correlation:** Integrated DNS/HTTP trigger correlation for blind SSRF and SQLi detection.

---

## Setup & Installation

### Requirements

- **Python 3.11+**
- **Go 1.26.2+**
- **Rust (Cargo) 1.75+**
- **Ollama** (Local LLM Server)

### Steps

1. **Initialize Environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Setup Headless Engine:**
   ```bash
   playwright install chromium
   ```

3. **Bootstrap Triple-Core:**
   ```bash
   python3 main.py bootstrap --force
   ```

---

## How to Use: The `whalerun` Directive

The `whalerun` command is the primary entry point for high-fidelity auditing.

### 1. Basic Audit
Standard scan including recursive crawling and multi-vector fuzzing:
```bash
python3 main.py whalerun http://example.com
```

### 2. Stealth & Anonymity
Activate Adaptive Pacing, Noise Injection, and Tor routing:
```bash
python3 main.py whalerun http://example.com --stealth --tor
```

### 3. Authentication & Identity Testing
Enable deep-logic testing for JWTs and multi-role authorization resilience:
```bash
python3 main.py whalerun http://example.com --brute-auth
```

### 4. Headless SPA Discovery (Looting)
Extract client-side storage, cookies, and identify hidden API endpoints:
```bash
python3 main.py whalerun http://example.com --loot
```

---

## Command Reference

| Flag | Feature | Impact |
| :--- | :--- | :--- |
| `--stealth` | Defensive Neutralization | Activates PID Ratelimiting, Noise Injection, and TLS Spoofing. |
| `--brute-auth`| Identity Neutralization | Executes JWT confusion and Multi-Role SessionMap testing. |
| `--loot` | SPA API Discovery | Spawns headless workers for DOM execution and storage looting. |
| `--tor` | Network Anonymity | Routes all traffic through SOCKS5 127.0.0.1:9050. |
| `--action` | Scope Control | `crawl` (discovery), `fuzz` (vulnerability), or `both`. |
| `-H, --header`| Custom Injection | Pass custom headers for authenticated sessions. |

### System Management
- `python3 main.py info`: Display triple-core architecture status.
- `python3 main.py bootstrap`: Recompile Kinetic (Go) and Orchestral (Rust) binaries.
- `python3 main.py report <file>`: Generate a technical Markdown/JSONL report.

---

## Disclaimer
BlueWhale is for **authorized security testing only**. The author is not responsible for any misuse or damage caused by this platform.
