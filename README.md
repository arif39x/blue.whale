# Blue Whale

![Blue Whale Logo](assets/Logo.png)

**Blue Whale** is a high performance fast vulnerability finding tool for web-apps (like SQLi, XSS, and SSRF).

---

## Features

- **Blazing Fast:** High-concurrency Go engine for crawling and testing.
- **Payload Templates:** Simple YAML files in `engine/templates/` let you easily add new vulnerability patterns.
- **WAF Evasion:** Automatically rotates User-Agents and headers to stay under the radar.
- **Smart Tech Detection:** Detects stacks (PHP, React, etc.) and picks the most effective tests automatically.
- **Deep Fuzzing:** Understands web parameters and tests them intelligently.

---

## 🛠️ Setup & Installation

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

2. **Setup Playwright (for DOM XSS testing):**

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
  python main.py scan -t http://example.com --profile stealth
  ```

### Custom Headers

Provide authorization tokens or session cookies:

```bash
python main.py scan -t http://example.com -H "Cookie: session=123"
```

---

## ⌨️ Command Reference

### Scan Options

| Command        | Description                                |
| :------------- | :----------------------------------------- |
| `-t, --target` | The URL of the target website              |
| `--profile`    | `standard`, `aggressive`, or `stealth`     |
| `--rpm`        | Set a specific speed (Requests Per Minute) |
| `--format`     | Output format (e.g., `pdf`, `json`)        |

### Management

| Command                                 | Description                            |
| :-------------------------------------- | :------------------------------------- |
| `python main.py report <results.jsonl>` | Convert scan results into a PDF report |
| `python main.py bootstrap --force`      | Rebuild the internal Go engine binary  |
| `python main.py paths`                  | Check and verify local system paths    |

---

## Disclaimer

Blue Whale is for **authorized security testing only**. Do not use it on systems you do not have explicit permission to test. The author is not responsible for any misuse or damage caused by this tool.
