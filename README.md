<div align="center">

```
                 _                    ____  _        _ _        
                / \   ___ _ __ ___  / ___|| |_ _ __(_) | _____ 
               / _ \ / __| '__/ _ \ \___ \| __| '__| | |/ / _ \
              / ___ \ (__| | | (_) | ___) | |_| |  | |   <  __/
             /_/   \_\___|_|  \___/ |____/ \__|_|  |_|_|\_\___|
                                                              v1.0
```

# AcroStrike

### Zero-Dependency VAPT Scanner — Zero False Positives

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue?logo=powershell&logoColor=white)](https://docs.microsoft.com/en-us/powershell/)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Acro Empire](https://img.shields.io/badge/Acro-Empire-ff6b35)](https://github.com/AcroEmpire)

**A pure PowerShell vulnerability assessment and penetration testing scanner that requires zero external tools, zero dependencies, and produces zero false positives.**

*Part of the [Acro Empire](https://github.com/acro777x/acromap) — alongside [AcroMap](https://github.com/AcroEmpire/AcroMap) & [AcroProbe](https://github.com/acro777x/AcroProbe)*

---

</div>

## 🎯 What is AcroStrike?

AcroStrike is a **single-file, pure PowerShell** VAPT (Vulnerability Assessment and Penetration Testing) scanner designed for security professionals. It performs 12 deep scan phases on any target domain and generates a comprehensive Markdown + JSON report — complete with confirmed vulnerabilities, CVSS scores, CWE references, and **automated exploit chain generation**.

> **No Python. No Node. No Go. No Kali. Just PowerShell.**

---

## ⚡ Key Features

| Feature | Description |
|---------|-------------|
| **🔒 Zero Dependencies** | Pure PowerShell 5.1+. No external tools, modules, or installations required |
| **🎯 Zero False Positives** | 4-layer verification system eliminates every known false positive source |
| **📊 12-Phase Deep Scan** | SSL/TLS → Tech Stack → Headers → HTTP Methods → Cookies → Files → Ports → Subdomains → JS Secrets → DNS → Forms → Report |
| **⛓️ Exploit Chain Engine** | Automatically chains confirmed vulnerabilities into real-world attack paths |
| **📝 Dual Reports** | Generates both human-readable Markdown and machine-parsable JSON |
| **🛡️ Evidence Collection** | Saves raw evidence (JS files, exposed configs, SSL certs) for audit trails |
| **🌐 Smart Subdomain Discovery** | Wildcard DNS detection prevents inflated subdomain counts |
| **🔑 Secret Scanner** | Detects JWT tokens, AWS keys, API keys, Stripe keys, and 11 other patterns in JavaScript |

---

## 🚀 Quick Start

### One-Line Run (Interactive)

```powershell
.\acrostrike.ps1
```
> You'll be prompted to enter a target domain.

### Direct Target

```powershell
.\acrostrike.ps1 -Target example.com
```

### Bypass Execution Policy (if needed)

```powershell
powershell -ExecutionPolicy Bypass -File acrostrike.ps1 -Target example.com
```

---

## 📋 Scan Phases

AcroStrike runs **12 sequential phases**, each building on the previous:

```
Phase  1/12  ─  SSL/TLS Certificate Analysis
Phase  2/12  ─  Technology Stack Fingerprinting
Phase  3/12  ─  Security Headers Audit
Phase  4/12  ─  HTTP Methods Analysis
Phase  5/12  ─  Cookie Security Analysis
Phase  6/12  ─  Sensitive File Discovery
Phase  7/12  ─  Port Scanning (29 ports)
Phase  8/12  ─  Subdomain Discovery (48 prefixes)
Phase  9/12  ─  JavaScript Analysis (Secrets + APIs)
Phase 10/12  ─  DNS Intelligence (SPF/DMARC/MX)
Phase 11/12  ─  Exploit Chain Generation
Phase 12/12  ─  Report Generation (MD + JSON)
```

---

## 🛡️ Zero False Positive System

AcroStrike v1.0 implements **4 anti-false-positive layers** that no other PowerShell scanner has:

### 1. Local Proxy / Antivirus SSL Detection
```
Problem:  Antivirus software (Norton, Kaspersky, etc.) intercepts SSL and replaces 
          certificates. Other scanners report this as "untrusted certificate" — a 
          false positive.
Solution: AcroStrike detects 12+ local proxy signatures and skips SSL cert 
          findings when local interception is detected.
```

### 2. Wildcard DNS Filtering
```
Problem:  Many domains have wildcard DNS (*.example.com → same IP). Subdomain 
          brute-force returns 48+ "found" subdomains — all false positives.
Solution: AcroStrike tests 2 random subdomains first. If both resolve, it 
          activates wildcard mode and only reports subdomains serving different 
          content than the wildcard catch-all.
```

### 3. HTTP Method Response Comparison
```
Problem:  CDNs like Cloudflare return HTTP 200 for PUT/DELETE requests but serve 
          the same page as GET. Other scanners flag this as "PUT enabled" — false.
Solution: AcroStrike hashes the GET response and compares PUT/DELETE responses. 
          Only flags methods that produce genuinely different responses.
```

### 4. CDN Source Map Exclusion
```
Problem:  Third-party CDN JavaScript files (jQuery, Bootstrap) often have .map 
          files. Other scanners report these as "exposed source maps" for YOUR site.
Solution: AcroStrike maintains a list of 18+ known CDN domains and skips their 
          source maps. Only first-party source maps are reported.
```

---

## 📊 Output Structure

After scanning, AcroStrike creates an organized output directory:

```
acrostrike_example.com/
├── VAPT_REPORT.md          # Full vulnerability report (Markdown)
├── VAPT_REPORT.json        # Machine-parsable report (JSON)
├── evidence/               # Raw evidence files
│   ├── ssl_analysis.txt    # SSL certificate details
│   ├── dns_records.txt     # DNS intelligence
│   ├── exposed_robots.txt  # robots.txt content
│   └── all_js_combined.txt # Combined JavaScript for analysis
├── js_files/               # Individual JS files downloaded
│   ├── main.js
│   └── vendor.js
└── pages/                  # Downloaded HTML pages
    └── index.html
```

---

## 📝 Report Format

AcroStrike generates professional-grade reports with:

### Vulnerability Entry
Each finding includes:

| Field | Description |
|-------|-------------|
| **ID** | Unique vulnerability identifier (e.g., `HDR-01`, `SSL-03`) |
| **Title** | Human-readable vulnerability name |
| **Severity** | CRITICAL / HIGH / MEDIUM / LOW |
| **CVSS** | CVSS v3.1 base score |
| **CWE** | Common Weakness Enumeration reference |
| **Location** | Exact URL or endpoint affected |
| **Evidence** | What was observed (raw proof) |
| **Impact** | What an attacker could do |
| **Remediation** | How to fix it |
| **Confirmed** | Boolean — only `True` findings are reported |

### Exploit Chain Entry
Each chain shows:
```
Chain 1: XSS via Missing CSP + Clickjacking
Severity: HIGH | Complexity: MEDIUM

  Step 1 : CONFIRMED: No Content-Security-Policy header
  Step 2 : ATTACK: Any XSS vulnerability becomes fully exploitable
  Step 3 : ATTACK: Injected script can load external resources
  Step 4 : RESULT: Cookie theft, credential harvesting
  Step 5 : AMPLIFIED: No X-Frame-Options enables clickjacking
```

---

## 🔍 What It Detects

### SSL/TLS
- Self-signed certificates
- Expired certificates
- Weak TLS protocols (SSLv3, TLS 1.0/1.1)
- Weak cipher suites (<128-bit)
- Missing HTTPS redirect

### Security Headers
- Missing `Strict-Transport-Security` (HSTS)
- Missing `Content-Security-Policy` (CSP)
- Missing `X-Frame-Options`
- Missing `X-Content-Type-Options`
- Missing `Referrer-Policy`
- Missing `Permissions-Policy`
- Weak CSP (`unsafe-inline` + `unsafe-eval`)
- CORS misconfiguration (wildcard, origin reflection)

### HTTP Methods
- TRACE (Cross-Site Tracing with header reflection verification)
- PUT (file upload — with GET response comparison)
- DELETE (resource deletion — with GET response comparison)

### Secrets in JavaScript
- AWS Access Keys (`AKIA...`)
- Google API Keys (`AIza...`)
- JWT Tokens (`eyJ...`)
- Private Keys (`-----BEGIN PRIVATE KEY-----`)
- Slack Tokens
- GitHub Tokens
- Stripe Keys
- SendGrid Keys
- Generic API keys, secrets, and passwords

### Sensitive Files (36 paths)
- `.env`, `.env.local`, `.env.production`
- `.git/HEAD`, `.git/config`
- `web.config`, `wp-config.php`
- `backup.sql`, `dump.sql`, `database.sql`
- `phpinfo.php`, `swagger.json`
- `server-status`, `server-info`
- And 22 more...

### Infrastructure
- 29 TCP ports scanned (FTP through MongoDB)
- 48 subdomain prefixes tested
- Dangerous port flagging (RDP, databases, Redis)
- SPF/DMARC/MX DNS analysis

---

## 🔗 Exploit Chain Patterns

AcroStrike can generate these exploit chains automatically:

| Chain | Trigger Vulnerabilities |
|-------|------------------------|
| **XSS Exploitation** | Missing CSP + Missing X-Frame-Options |
| **SSL Stripping** | No HSTS + No HTTPS redirect |
| **Session Hijacking** | Missing cookie flags + CORS misconfiguration |
| **Server Takeover** | Exposed config files + version disclosure |
| **Hardcoded Secrets** | JWT/API keys in JavaScript |
| **Database Breach** | Exposed DB ports + default configs |
| **Full Infrastructure** | Multiple chained vectors |

---

## ⚙️ Requirements

| Requirement | Version |
|-------------|---------|
| **PowerShell** | 5.1+ (Windows built-in) |
| **OS** | Windows 7/8/10/11 or Server 2012+ |
| **Network** | Direct internet access to target |
| **.NET** | 4.5+ (Windows built-in) |
| **External Tools** | **NONE** |

---

## 🔒 Legal & Ethics

> **⚠️ IMPORTANT: Only scan targets you own or have written authorization to test.**

AcroStrike is designed for:
- ✅ Authorized penetration testing engagements
- ✅ Security auditing of your own infrastructure
- ✅ Bug bounty programs (within scope)
- ✅ Compliance assessments (PCI DSS, ISO 27001, OWASP)
- ❌ **NOT for unauthorized scanning of third-party systems**

This tool performs **passive reconnaissance and active probing** on the public surface. It does **not** attempt exploitation, upload files, or modify target systems.

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/AcroEmpire/AcroStrike.git

# Navigate to the directory
cd AcroStrike

# Run the scanner
powershell -ExecutionPolicy Bypass -File acrostrike.ps1 -Target example.com
```

No `pip install`. No `npm install`. No `apt-get`. Just clone and run.

---

## 🗺️ Acro Empire

AcroStrike is part of the **Acro Empire** — a suite of security and development tools:

| Tool | Description |
|------|-------------|
| [**AcroMap**](https://github.com/AcroEmpire/AcroMap) | Network mapping and visualization |
| [**AcroProbe**](https://github.com/AcroEmpire/AcroProbe) | Infrastructure probing and recon |
| [**AcroStrike**](https://github.com/AcroEmpire/AcroStrike) | VAPT scanner with zero false positives |

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/new-check`)
3. Add your vulnerability check following the `Add-Vuln` pattern
4. Test against at least 3 different target types
5. Submit a pull request

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built with ⚡ PowerShell | Part of the Acro Empire**

*If AcroStrike helped you find real vulnerabilities, give it a ⭐*

</div>
