# Project BlueWhale

![Blue Whale Logo](assets/Logo.png)

**BlueWhale** is a high-fidelity vulnerability orchestration platform engineered for advanced offensive-defensive auditing. It is designed around a **deterministic execution core**, an **optional intelligence layer**, and a **unified evidence pipeline**.

---

## Core Philosophy

1. **Deterministic First**: All vulnerability detection is grounded in reproducible, evidence-based logic. No model is required to validate findings.
2. **Model as Augmentation**: LLMs assist in classification, triage, and summarization but never act as the primary source of truth.
3. **Evidence-Centric**: Every action produces artifacts (HTTP responses, DOM snapshots, storage dumps) that form the authoritative dataset.
4. **Modular Execution**: Each capability is an independent command, suitable for CI/CD or targeted manual audits.

---

## Architecture: The Triple-Core Model

- **Kinetic Core (Go)**: High-performance network engine with custom TCP/TLS stacks and PID-controlled rate limiting.
- **Orchestral Layer (Rust)**: High-speed LLM management for parallel mutation and analysis.
- **Cognitive Core (Python)**: Orchestration plane that manages the lifecycle, evidence pipeline, and deterministic rules.

---

## Setup & Installation

### Requirements
- **Python 3.11+**
- **Go 1.26.2+**
- **Rust (Cargo) 1.75+**
- **Ollama** (Optional for AI features)

### Steps
1. **Initialize Environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. **Setup Browser Engine**:
   ```bash
   playwright install chromium
   ```
3. **Bootstrap Binaries**:
   ```bash
   python3 main.py bootstrap --force
   ```

---

## The `whalerun` Directive: Command Reference

BlueWhale uses a modular command structure. Each command can be run independently.

### 1. Initialization
Prepare the workspace and configuration.
```bash
python3 main.py init
```

### 2. Scanning (Deterministic)
Perform endpoint probing and browser-based rule detection.
```bash
python3 main.py scan --target http://example.com
```

### 3. Crawling & Discovery
SPA navigation and hidden route discovery.
```bash
python3 main.py crawl --target http://example.com --depth 3
```

### 4. Authentication Testing
Multi-role session validation and authorization boundary testing.
```bash
python3 main.py auth --target http://example.com --roles admin,user
```

### 5. Looting
Extract localStorage, IndexedDB, and hidden API endpoints.
```bash
python3 main.py loot --target http://example.com
```

### 6. AI-Assisted Analysis
Triage findings using the optional Intelligence Plane.
```bash
python3 main.py analyze --model ollama
# Or disable AI completely
python3 main.py analyze --no-llm
```

### 7. Reporting
Generate technical reports from the evidence plane.
```bash
python3 main.py report --format json --output results/
```

---

## Global Flags

| Flag | Description |
| :--- | :--- |
| `--target, -t` | Target URL for the operation. |
| `--config, -c` | Path to a custom `settings.yaml`. |
| `--no-llm` | Force disable all AI-augmented features. |
| `--force` | (Bootstrap) Recompile all core binaries. |

---

## Evidence Model
All findings map to stored artifacts in `data/evidence/`:
- **Artifacts**: Raw HTTP data, DOM snapshots, Screenshots.
- **Findings**: Verified vulnerabilities linked to specific artifacts.

---

## Disclaimer
BlueWhale is for **authorized security testing only**. The author is not responsible for any misuse or damage caused by this platform.
