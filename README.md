<div align="center">

```
 ██████╗███████╗██████╗ ██████╗ ███████╗██████╗ ██╗   ██╗███████╗
██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██║   ██║██╔════╝
██║     █████╗  ██████╔╝██████╔╝█████╗  ██████╔╝██║   ██║███████╗
██║     ██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██╗██║   ██║╚════██║
╚██████╗███████╗██║  ██║██████╔╝███████╗██║  ██║╚██████╔╝███████║
 ╚═════╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

### The 3-Headed Hybrid Security Auditor (SAST + DAST + SCA)

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker Support](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![Cybersecurity Triad](https://img.shields.io/badge/security-SAST%20%7C%20DAST%20%7C%20SCA-red.svg)](#features)

*Authored by **Boymirza Rejavaliyev** | Cybersecurity Researcher & Engineer*

---

</div>

## 📌 Overview

**CERBERUS** is an open-source, high-performance hybrid application security auditor. Inspired by the mythical three-headed hound of the underworld, Cerberus unifies the **Holy Trinity of Application Security (AppSec)** into a single unified CLI engine:

1. **Head 1: SAST (Static Application Security Testing)** — White-box deep source code auditing.
2. **Head 2: DAST (Dynamic Application Security Testing)** — Black-box web reconnaissance and attack surface mapping.
3. **Head 3: SCA (Software Composition Analysis)** — Supply chain CVE scanner for third-party dependencies.

---

## ⚡ The 3 Heads Architecture

```
                  ┌───────────────────────────────┐
                  │       CERBERUS ENGINE         │
                  └──────────────┬────────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         │                       │                       │
         ▼                       ▼                       ▼
   ┌───────────┐           ┌───────────┐           ┌───────────┐
   │  HEAD 1   │           │  HEAD 2   │           │  HEAD 3   │
   │   SAST    │           │   DAST    │           │    SCA    │
   │ (Source)  │           │   (Web)   │           │   (CVE)   │
   └─────┬─────┘           └─────┬─────┘           └─────┬─────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                                 ▼
                  ┌───────────────────────────────┐
                  │      UNIFIED AUDIT REPORT     │
                  │   [Terminal | HTML | JSON]    │
                  └───────────────────────────────┘
```

### 1. 🔍 Head 1: SAST (White-Box Code Audit)
* **Secret Leak Detection:** Scans for hardcoded AWS keys, private cryptographic keys, connection strings, and API secrets.
* **Dangerous Sinks:** Traces dynamic user inputs into critical functions:
  * SQL Injection (`mysqli_query`, `$pdo->query`, raw DB executions)
  * Command Injection (`system`, `exec`, `shell_exec`, `subprocess`)
  * Local File Inclusion / Path Traversal (`include`, `file_get_contents`)
  * Insecure Deserialization (`unserialize`, Python `pickle`)
  * Cross-Site Scripting (XSS) in direct output templates

### 2. 🌐 Head 2: DAST (Black-Box Web Recon)
* **Security Headers Audit:** Evaluates CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.
* **Sensitive File & Backup Probing:** Concurrently tests for exposed `/.git/HEAD`, `/.env`, `/phpinfo.php`, `/backup.zip`, `robots.txt`, and admin portals.
* **CORS Misconfiguration:** Detects unauthenticated origin reflection with credentials.
* **Server Fingerprinting:** Identifies disclosed server daemon software and backend framework versions.

### 3. 📦 Head 3: SCA (Supply Chain & CVE Analysis)
* **Manifest Parsing:** Analyzes `requirements.txt` (Python), `package.json` (Node.js), and `composer.json` (PHP).
* **CVE Intelligence:** Cross-references installed versions against known vulnerability databases and OSV (Open Source Vulnerabilities) API.
* **Actionable Remediation:** Pinpoints exact minimum safe versions required to patch identified CVEs.

---

## 🚀 Quickstart & Installation

### Option 1: Native Installation
```bash
# 1. Clone repository
git clone https://github.com/phantom/cerberus.git
cd cerberus

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run audit
python3 cerberus.py --help
```

### Option 2: Docker Container (One-Liner)
```bash
# Build container image
docker build -t cerberus-auditor .

# Run scan on local directory
docker run --rm -v $(pwd):/scan cerberus-auditor --code /scan --html /scan/audit.html
```

---

## 💻 Usage & Command Guide

### 1. Full Hybrid Triad Audit (Recommended)
Run all 3 heads against a project and generate an interactive HTML report:
```bash
python3 cerberus.py --code /var/www/html --deps /var/www/html --url https://target.local --html report.html
```

### 2. Source Code Only (SAST)
Audit source code directory for vulnerabilities and hardcoded credentials:
```bash
python3 cerberus.py --code ./src --html sast_report.html
```

### 3. Web Recon Only (DAST)
Audit an external web perimeter:
```bash
python3 cerberus.py --url https://example.com/
```

### 4. Dependency CVE Scan (SCA)
Audit dependencies for known CVEs:
```bash
python3 cerberus.py --deps ./my-project/
```

### 5. Export to JSON (CI/CD Pipeline Integration)
```bash
python3 cerberus.py --code ./src --json results.json
```

---

## 📊 Sample Output Preview

```text
╭────────────────────────── AUDIT EXECUTIVE SUMMARY ───────────────────────────╮
│ CRITICAL: 4  |  HIGH: 2  |  MEDIUM: 2  |  LOW/INFO: 0                        │
╰──────────────────────────────────────────────────────────────────────────────╯
                   HEAD 1: SAST FINDINGS (SOURCE CODE AUDIT)                    
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Rule / Vulnerability ┃ Location            ┃ Snippet / Match      ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━┩
│ CRITICAL │ Hardcoded AWS Access │ test_target/vulner… │ $aws_key =           │
│          │ Key (SEC-001)        │                     │ "AKIA1234567890ABCD… │
│ CRITICAL │ Command Execution    │ test_target/vulner… │ system("ping -c 4 "  │
│          │ Sink (CMD-001)       │                     │ . $cmd);             │
│ CRITICAL │ SQL Query Execution  │ test_target/vulner… │ mysqli_query($conn,  │
│          │ with Variable        │                     │ $query);             │
└──────────┴──────────────────────┴─────────────────────┴──────────────────────┘
```

---

## 🛡️ License

This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.

## 🤝 Author & Contributions

* **Author:** Boymirza Rejavaliyev
* **GitHub:** [https://github.com/phantom](https://github.com/phantom)
* **Email:** boymirzarejavaliyev2003@gmail.com
* Feedback, issues, and PR contributions are welcome!
