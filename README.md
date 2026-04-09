# Blue Whale

![Blue Whale Logo](assets/Logo.png)

> Blue Whale is a Web Vulnerability Scanning Tool...

---

## Requirements

### System

- Python >= 3.11
- Go >= 1.21
- `jq`, `bash`

### Python dependencies

```bash
pip install -r requirements.txt
```

### Go

```bash
cd engine && go build -o ../bin/whale-engine .
```

Or run the bootstrap script on first launch - it will detect missing binaries and compile automatically.

---

## Usage

### GUI mode

```bash
python main.py
```

### CLI mode

```bash
# General help
python main.py --help

# 1. Bootstrap 
python main.py bootstrap

# 2. Basic Scan
python main.py scan --target https://example.com

# 3. Scan with Profile (full, fast, stealth)
python main.py scan --target https://example.com --profile full

# 4. Authenticated Scan (Custom Headers)
python main.py scan --target https://example.com -H "Cookie: session=123"

# 5. Export results (json, csv, pdf, html)
python main.py scan --target https://example.com --format pdf --output ./reports

# 6. Generate report from existing results
python main.py report reports/whale_12345.jsonl --target https://example.com --format html

# 7. Check project paths
python main.py paths
```

---

## Configuration

All runtime parameters  in `config/settings.yaml` - Copy and edit before first run:

```bash
cp config/settings.yaml.example config/settings.yaml
```


---

