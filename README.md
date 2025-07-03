# GitHub .suo File Malware Scanner 🔍🛡️


Scans GitHub repositories for suspicious `.suo` files using:
- **YARA rules** (custom pattern matching)
- **VirusTotal API** (70+ antivirus engines)

```python
# Quick Start
python suo_scanner.py \
  --github-url https://github.com/example/repo \
  --vt-key YOUR_VIRUSTOTAL_KEY
```

## Table of Contents
1. [Features](#features)
2. [Setup](#setup)
3. [Usage](#usage)
4. [YARA Rules](#yara-rules)
5. [CI/CD](#cicd)
6. [Security](#security)

## Features
- Detect malicious patterns in `.suo` files
- Custom YARA rule support
- VirusTotal integration
- GitHub Actions ready

## Setup
```bash
# 1. Clone repository
git clone https://github.com/Sh1imaz1/suo_files_checker.git
cd suo_files_checker

# 2. Install dependencies
pip install -r requirements.txt
```

## Usage
### Basic Scan
```bash
python suo_scanner.py \
  --github-url REPO_URL \
  --vt-key VIRUSTOTAL_KEY
```

### Advanced Options
| Parameter | Description |
|-----------|-------------|
| `--github-token` | For private repos |
| `--yara-rules` | Custom rules directory |
| `--max-repos` | Limit scanned repos |

## YARA Rules
1. Create rules in `.yar` files:
```yara
rule Example {
  meta:
    description = "Detects X"
  strings:
    $suspicious = "cmd.exe" nocase
  condition:
    $suspicious
}
```
2. Place in `./rules` folder

## CI/CD
### GitHub Actions Example
```yaml
- name: Scan .suo Files
  env:
    VT_KEY: ${{ secrets.VT_KEY }}
  run: |
    python suo_scanner.py \
      --github-url https://github.com/${{ github.repository }} \
      --vt-key $VT_KEY
```

## Security
- 🔒 Never commit API keys
- ⚠️ Review findings manually
- 🔄 Rotate tokens regularly

---
📝 **License**: MIT  
🐛 **Report Issues**: [Here](https://github.com/Sh1imaz1/suo_files_cheacker/issues)
