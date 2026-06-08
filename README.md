<div align="center">

![AcroStrike Banner](acro_empire_strike.png)


```

# AcroStrike v2.0

### 20-Phase VAPT Scanner — Zero Dependencies, Zero False Positives

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue?logo=powershell&logoColor=white)](https://docs.microsoft.com/en-us/powershell/)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Acro Empire](https://img.shields.io/badge/Acro-Empire-ff6b35)](https://github.com/acro777x)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%20Mapped-orange)](https://owasp.org/www-project-top-ten/)

**A pure PowerShell VAPT scanner with 20 deep scan phases, OWASP Top 10 mapping, exploit chain generation, and zero false positives.**

*Part of the [Acro Empire](https://github.com/acro777x/) — alongside [AcroMap](https://github.com/acro777x/acromap) & [AcroProbe](https://github.com/acro777x/AcroProbe)*

---

</div>

## 🆕 What's New in v2.0

| Feature | v1.0 | v2.0 |
|---------|------|------|
| **Scan Phases** | 12 | **20** |
| **Sensitive File Paths** | 36 | **60+** |
| **Exploit Chains** | Basic | **Risk-scored with confidence** |
| **OWASP Mapping** | ❌ | ✅ Full Top 10 2021 |
| **WAF Detection** | ❌ | ✅ Cloudflare, Akamai, AWS, Sucuri |
| **Domain Intel (RDAP)** | ❌ | ✅ Age/registrar analysis |
| **CMS Checks** | ❌ | ✅ WordPress/Joomla/Drupal |
| **API Probing** | ❌ | ✅ Auth bypass detection |
| **HTML Report** | ❌ | ✅ Dark-themed self-contained |
| **Email Deep Scan** | Basic | ✅ MTA-STS, BIMI, DANE |
| **Scan Profiles** | ❌ | ✅ `-Fast`, `-Quiet` modes |
| **Vulnerable JS Libs** | ❌ | ✅ jQuery, Angular, Lodash, Bootstrap |
| **Report Formats** | MD + JSON | **MD + JSON + HTML** |

---

## 🚀 Quick Start

```powershell
# Interactive
.\acrostrike.ps1

# Direct target
.\acrostrike.ps1 -Target example.com

# Fast mode (skip ports, subdomains, CMS, API)
.\acrostrike.ps1 -Target example.com -Fast

# Quiet mode (no terminal output)
.\acrostrike.ps1 -Target example.com -Quiet

# Bypass execution policy
powershell -ExecutionPolicy Bypass -File acrostrike.ps1 -Target example.com
```

> **No Python. No Node. No Go. No Kali. Just PowerShell.**

---

## 📋 All 20 Scan Phases

```
Phase  1/20  ─  SSL/TLS Certificate Analysis
Phase  2/20  ─  Technology Stack Fingerprinting
Phase  3/20  ─  Security Headers Audit
Phase  4/20  ─  HTTP Methods Analysis
Phase  5/20  ─  Cookie Security Analysis
Phase  6/20  ─  Sensitive File Discovery (60+ paths)
Phase  7/20  ─  Port Scanning (29 ports)
Phase  8/20  ─  Subdomain Discovery (48 prefixes)
Phase  9/20  ─  JavaScript Analysis (Secrets + Vulnerable Libraries)
Phase 10/20  ─  DNS Intelligence (SPF/DMARC/MX)
Phase 11/20  ─  Form & Input Analysis (CSRF/Autocomplete)
Phase 12/20  ─  WAF/CDN Detection          🆕
Phase 13/20  ─  Domain Intelligence (RDAP)  🆕
Phase 14/20  ─  Redirect Chain Analysis     🆕
Phase 15/20  ─  CMS-Specific Checks         🆕
Phase 16/20  ─  API Endpoint Probing        🆕
Phase 17/20  ─  Content Analysis            🆕
Phase 18/20  ─  Email Security Deep Scan    🆕
Phase 19/20  ─  OWASP Top 10 Mapping        🆕
Phase 20/20  ─  Exploit Chain Generation (Enhanced)
```

---

## 🛡️ Zero False Positive System

| Layer | What it prevents |
|-------|-----------------|
| **Local Proxy Detection** | Norton/Kaspersky/Avast SSL interception → skips cert findings |
| **Wildcard DNS Filter** | `*.example.com` catch-all → only reports unique subdomains |
| **HTTP Method Baseline** | CDN returns 200 for PUT/DELETE → compares with GET response hash |
| **CDN Source Map Skip** | 18+ known CDN domains → only flags YOUR source maps |
| **Soft 404 Detection** | Custom error pages → baseline comparison prevents false file discoveries |

---

## 📊 Output Structure

```
acrostrike_example.com/
├── VAPT_REPORT.md          # Markdown report
├── VAPT_REPORT.json        # Machine-parsable JSON
├── VAPT_REPORT.html        # Self-contained dark-theme HTML 🆕
├── evidence/
│   ├── ssl_analysis.txt
│   ├── domain_intel.txt    🆕
│   ├── redirect_chain.txt  🆕
│   └── exposed_*.txt
├── js_files/
└── pages/
```

---

## ⛓️ Exploit Chains

Each chain includes **composite risk score** and **confidence rating**:

| Chain | Triggers | Confidence |
|-------|----------|------------|
| **MITM/SSL Strip** | No HSTS + No HTTPS redirect | HIGH |
| **XSS Exploitation** | Missing CSP + Missing XFO | HIGH |
| **Phishing Infrastructure** | Young domain + No SPF/DMARC 🆕 | HIGH |
| **CMS Takeover** | CMS version + Admin panel 🆕 | MEDIUM |
| **API Abuse** | Unauth API + Exposed secrets 🆕 | HIGH |
| **Email Spoofing** | Weak SPF + No DMARC | HIGH |
| **Full Infrastructure** | 10+ vulns, 3+ OWASP categories 🆕 | HIGH |

---

## ⚙️ Requirements

| Requirement | Version |
|-------------|---------|
| **PowerShell** | 5.1+ (Windows built-in) |
| **OS** | Windows 7/8/10/11 or Server 2012+ |
| **External Tools** | **NONE** |

---

## 📦 Installation

```bash
git clone https://github.com/acro777x/AcroStrike.git
cd AcroStrike
powershell -ExecutionPolicy Bypass -File acrostrike.ps1 -Target example.com
```

---

## 🔒 Legal

> **⚠️ Only scan targets you own or have written authorization to test.**

- ✅ Authorized penetration testing
- ✅ Bug bounty programs (within scope)
- ✅ Compliance assessments (PCI DSS, ISO 27001, OWASP)
- ❌ **NOT for unauthorized scanning**

---

## 🗺️ Acro Empire

| Tool | Description |
|------|-------------|
| [**AcroMap**](https://github.com/acro777x/acromap) | Network mapping and visualization |
| [**AcroProbe**](https://github.com/acro777x/AcroProbe) | Infrastructure probing and recon |
| [**AcroStrike**](https://github.com/acro777x/AcroStrike) | 20-phase VAPT scanner |

---

<div align="center">

**Built with ⚡ PowerShell | Part of the Acro Empire**

*If AcroStrike helped you find real vulnerabilities, give it a ⭐*

</div>
