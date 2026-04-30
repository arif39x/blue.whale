# Project BlueWhale

![Blue Whale Logo](assets/Logo.png)

**BlueWhale** is an advanced, high-fidelity vulnerability orchestration platform engineered for offensive-defensive auditing. It employs a **Kinetic-Cognitive** dual-core model, synchronizing a high-performance Go network engine with a Python-based Small Language Model (SLM) for semantic intent analysis and polymorphic execution.

---

## Core Philosophy
> "Security is a temporary state of resistance. Nothing is absolute. There must be a vulnerability; BlueWhale will find it."

---

## High-Fidelity Features

- **Kinetic-Cognitive Orchestration:** Asynchronous IPC between the Python "Brain" and Go "Executor" for real-time intent serialization and defensive neutralization.
- **Defensive Neutralization Matrix:**
  - **Gaussian Jitter:** Statistical pacing using $T_{request} = \mu + \sigma \cdot N(0, 1)$ to evade anycast-based anomaly detection.
  - **TLS Fingerprinting:** Dynamic JA3/JA4 spoofing to mimic legitimate browser stacks (Chrome, Firefox, Safari).
  - **Semantic Mutator:** SLM-driven polymorphic mutation for WAF rule evasion (e.g., `HAVING` clause injection, Unicode obfuscation).
- **Identity Neutralization:** Deep-logic testing for JWT algorithm confusion, none-alg injection, and OAuth2 resilience.
- **Recursive Headless Discovery:** Playwright-integrated SPA crawling to identify hidden API endpoints and DOM-based XSS.
- **Out-of-Band (OAST) Correlation:** Integrated DNS/HTTP trigger correlation for blind SSRF and SQLi detection.

---

## Setup & Installation

### Requirements

- **Python 3.11+**
- **Go 1.26.2+**

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

3. **Build Kinetic Core:**
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
Activate Gaussian jitter, TLS fingerprinting, and Tor routing:
```bash
python3 main.py whalerun http://example.com --stealth --tor
```

### 3. Authentication & Identity Testing
Enable deep-logic testing for JWTs and authentication resilience:
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
| `--stealth` | Defensive Neutralization | Activates Gaussian Jitter and JA3 Fingerprinting. |
| `--brute-auth`| Identity Neutralization | Executes JWT algorithm confusion and None-Alg testing. |
| `--loot` | SPA API Discovery | Spawns headless workers for DOM execution and storage looting. |
| `--tor` | Network Anonymity | Routes all traffic through SOCKS5 127.0.0.1:9050. |
| `--action` | Scope Control | `crawl` (discovery), `fuzz` (vulnerability), or `both`. |
| `-H, --header`| Custom Injection | Pass custom headers for authenticated sessions. |

### System Management
- `python3 main.py info`: Display hybrid-core architecture status.
- `python3 main.py bootstrap`: Recompile the Kinetic Core binary.
- `python3 main.py report <file>`: Generate a technical PDF/HTML report.

---

## Disclaimer
BlueWhale is for **authorized security testing only**. The author is not responsible for any misuse or damage caused by this platform.
