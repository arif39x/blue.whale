# Blue Whale

![Blue Whale Logo](assets/Logo.png)

**Blue Whale** is a high-performance, autonomous vulnerability finding tool for web-apps. It combines a blazing-fast Go engine with a Python orchestrator to perform deep security auditing, including SPA emulation and privilege escalation testing.

---

## Features

- **Blazing Fast Crawling & Fuzzing:** High-concurrency Go engine for crawling and differential analysis.
- **Advanced Headless Emulation:** Playwright integration with stealth plugins to bypass WAFs/Captchas, execute active DOM payloads, and loot client-side storage.
- **Dynamic Session Pivoting:** Automatically detects leaked session tokens (like JWTs) and spawns isolated, authenticated contexts to test privilege escalation.
- **Deep Deserialization & SSRF:** Recursive serialization mutation for JSON/GraphQL and dynamic OAST redirects for infrastructure testing (e.g., AWS Metadata extraction).
- **Payload Templates:** Simple YAML files in `engine/templates/` let you easily add new vulnerability patterns.
- **WAF Evasion:** Applies complex transform chains and automatically rotates User-Agents/headers to stay under the radar.

> **Note:** For a complete breakdown of the system components and data flow, please read the [**System Architecture Guide**](ARCHITECTURE.md).

---

## Setup & Installation

### Requirements

- **Python 3.11+**
- **Go 1.24+**

### Steps

1. **Initialize Python Environment:**

   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Setup Playwright (for DOM XSS & Stealth testing):**

   ```bash
   playwright install chromium
   ```

3. **Build the Scanning Engine:**
   ```bash
   python main.py bootstrap --force
   ```

---

## How to Use

### Basic Scan

Fastest way to start scanning a target:

```bash
python main.py scan --target http://example.com
```

### Advanced Scanning Profiles

- **Aggressive:** Higher speed and deeper testing.
  ```bash
  python main.py scan -t http://example.com --profile aggressive
  ```
- **Stealth:** Slower speed with randomized delays to bypass WAFs.
  ```bash
  python main.py scan -t http://example.com --profile stealth --evasion-level high
  ```

### Authentication Resilience & Pivoting

Test for credential stuffing on login forms and track privilege escalation:

```bash
python main.py scan -t http://example.com --brute-auth
```

### Custom Headers

Provide authorization tokens or session cookies:

```bash
python main.py scan -t http://example.com -H "Cookie: session=123"
```

---

## ⌨️ Command Reference

### Scan Options

| Command           | Description                                |
| :---------------- | :----------------------------------------- |
| `-t, --target`    | The URL of the target website              |
| `--profile`       | `standard`, `aggressive`, or `stealth`     |
| `--rpm`           | Set a specific speed (Requests Per Minute) |
| `--evasion-level` | Browser stealth level (`none`, `low`, `high`) |
| `--brute-auth`    | Enable credential stuffing & auth testing  |
| `--format`        | Output format (e.g., `pdf`, `json`)        |

### Management

| Command                                 | Description                            |
| :-------------------------------------- | :------------------------------------- |
| `python main.py report <results.jsonl>` | Convert scan results into a PDF report |
| `python main.py bootstrap --force`      | Rebuild the internal Go engine binary  |
| `python main.py paths`                  | Check and verify local system paths    |

---

## Disclaimer

Blue Whale is for **authorized security testing only**. Do not use it on systems you do not have explicit permission to test. The author is not responsible for any misuse or damage caused by this tool.
