# Moriarty

> Moriarty is a Web Vuenability Scanning Tool...

---

## Requirements

### System

- Python ≥ 3.11
- Go ≥ 1.21
- `jq`, `bash`

### Python dependencies

```bash
pip install -r requirements.txt
```

### Go

```bash
cd engine && go build -o ../bin/moriarty-engine .
```

Or run the bootstrap script on first launch — it will detect missing binaries and compile automatically.

---

## Usage

### GUI mode

```bash
python main.py
```

### CLI mode

```bash
python main.py --help
python main.py scan --target https://example.com --profile full
```

---

## Configuration

All runtime parameters live in `config/settings.yaml` — **no hardcoded values** anywhere in the codebase. Copy and edit before first run:

```bash
cp config/settings.yaml.example config/settings.yaml
```

Key settings: binary paths, RPS limits, timeouts, severity filters, User-Agent pool path.

---

## Data Flow

```
main.py  →  sh/pipe.sh  →  Katana (recon) ---──┐
                                               ├─ jq strip  →  Nuclei (vuln scan)
                                               │
                                        Python parser (Pydantic)
                                               │
                                    GUI table / CLI colour output
                                               │
                                        core/reporter.py  →  PDF / HTML
```
