# BlueWhale Command Reference Guide

This document describes the modular command structure of BlueWhale, designed for granular reconnaissance and vulnerability testing with enhanced stealth.

## Global Stealth Flags
The following flags are available across all primary scanning commands:
- `--proxy <URL>`: Route traffic through a specific SOCKS5 or HTTP proxy (e.g., `socks5://127.0.0.1:1080`).
- `--tor`: Shorthand to route all traffic (Go engine and Headless Browser) through a local Tor daemon (defaults to `127.0.0.1:9050`).
- `--evasion-level [none|low|high]`: Control browser fingerprint randomization and stealth JS injection.

---

## Commands

### 1. `scan`
The monolithic command that performs a full end-to-end audit.
- **Action:** Crawl -> Fuzz -> Loot.
- **Example:**
  ```bash
  python main.py scan --target https://example.com --tor --severity critical,high
  ```

### 2. `crawl`
Perform spidering, directory brute-forcing, and endpoint discovery.
- **Action:** Discovery only.
- **Output:** Discovered nodes are logged and saved to the `reports/` directory.
- **Example:**
  ```bash
  python main.py crawl --target https://example.com --show-nodes
  ```

### 3. `fuzz`
Perform targeted vulnerability fuzzing on a pre-defined list of URLs.
- **Action:** Template-based fuzzing only.
- **Input:** A text file containing URLs/nodes.
- **Example:**
  ```bash
  python main.py fuzz --nodes reports/whale_discovered.jsonl --severity medium,high
  ```

### 4. `loot`
Run the headless browser to extract sensitive client-side data.
- **Action:** Storage/Cookie extraction only.
- **Example:**
  ```bash
  python main.py loot --target https://example.com/dashboard --evasion-level high
  ```

### 5. `oast`
Standalone listener for Out-of-Band interactions.
- **Action:** Monitor DNS/HTTP callbacks.
- **Example:**
  ```bash
  python main.py oast
  ```

---

## Result Storage
All findings, logs, and reports are automatically stored in the `reports/` directory:
- **JSONL:** Raw machine-readable findings.
- **HTML:** Interactive human-readable security reports.
- **CSV:** Tabular export of discovered vulnerabilities.
- **PDF:** Executive summary (requires `weasyprint`).

## Stealth Tips
- Always use `--tor` if you are scanning from a sensitive network.
- Combine `--proxy` with custom `--header "User-Agent: ..."` for maximum camouflage.
- Use `crawl` first, manually prune the nodes list, then use `fuzz` to reduce noise on target servers.
