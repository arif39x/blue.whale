# Blue Whale

![Blue Whale Logo](assets/Logo.png)

> **Blue Whale** is a high-performance vulnerability discovery engine designed for advanced penetration testing.

---

## Blue Whale Updates

I recently completed a massive architectural overhaul, moving from a standard hybrid scanner into a deterministic, state-of-the-art vulnerability engine.

### Evolution Comparison

| Feature                | Legacy (v2.0)                             | Current (v3.0 - Raw Protocol)                                 |
| :--------------------- | :---------------------------------------- | :------------------------------------------------------------ |
| **IPC Mechanism**      | JSON over STDIN/STDOUT Pipes              | **Unix Domain Sockets (UDS) + MessagePack**                   |
| **Network Stack**      | Go `net/http` (Standard)                  | **Raw TCP Sockets + `utls`**                                  |
| **TLS Fingerprinting** | Standard Go Handshake (Easily Blocked)    | **JA3/JA4 Spoofing** (Mimics Chrome 120)                      |
| **Protocol Control**   | Managed by library (Normalizes malformed) | **Byte-Level Control** (Enables Smuggling/Malformed requests) |
| **Scanning Mode**      | Signature-based (Regex)                   | **Stateful, Differential & OOB (OAST)**                       |
| **OAST Support**       | None (Blind to async vulns)               | **Integrated Async DNS/HTTP Listener**                        |
| **Performance**        | I/O Bound (Serialization lag)             | **Network Bound** (Zero-copy binary IPC)                      |
| **UI Aesthetic**       | Standard Modern Dark                      | **Dark Web Hacker Terminal** (Matrix-style)                   |

---

## What I added.

- **JA3/JA4 TLS Spoofing:** Bypass modern WAFs by mimicking browser fingerprints.
- **Integrated OAST (Out-of-Band Testing):** Detect Blind SSRF, OOB SQLi, and XXE via our built-in responder.
- **Raw Protocol Fuzzing:** Send deliberately malformed HTTP headers and frames to find deep protocol-level vulnerabilities like Request Smuggling.
- **Hacker Terminal UI:** A completely overhauled GUI and CLI experience inspired by Matrix aesthetics and dark-web terminals.

---

## Requirements

### System

- **Python >= 3.11**
- **Go >= 1.24**
- `jq`, `bash`

### Installation

1. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Bootstrap the engine (rebuilds the optimized Go core):
   ```bash
   python main.py bootstrap --force
   ```

---

## Usage

### GUI Mode

```bash
python main.py
```

### CLI Mode

```bash
# 1. Start a high-performance scan
python main.py scan --target <target> --profile aggressive

# 2. Authenticated scan with stealth mode
python main.py scan --target <target> --profile stealth -H "Header: value"

# 3. View OAST identifiers and real-time hits
# (OAST is automatically handled by the engine)
```

---

## Configuration

Runtime parameters are located in `config/settings.yaml`. You can configure local listeners and stealth parameters there.

---

_Disclaimer: Blue Whale is intended for authorized security testing only. The author is not responsible for any misuse of this tool.And Currently its in Development Phase._
