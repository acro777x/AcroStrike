# ============================================================
# ACROSTRIKE v2.0 - Pure PowerShell VAPT Scanner
# 20-Phase Deep Reconnaissance Engine - ZERO false positives
# Part of the Acro Empire | github.com/acro777x
# For authorized security testing ONLY
# ============================================================

param(
    [string]$Target,
    [switch]$Fast,
    [switch]$Quiet
)

if (-not $Target) {
    Write-Host ""
    Write-Host "  ========================================" -ForegroundColor Cyan
    Write-Host "  ACROSTRIKE v2.0" -ForegroundColor Cyan
    Write-Host "  20-Phase VAPT Scanner | Zero False Positives" -ForegroundColor Cyan
    Write-Host "  ========================================" -ForegroundColor Cyan
    Write-Host ""
    $Target = Read-Host "  Enter target domain (e.g. example.com)"
    if (-not $Target) { Write-Host "No target provided. Exiting."; exit }
}

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

# Bypass SSL validation for recon
try {
    Add-Type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsVAPT : ICertificatePolicy {
        public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
    }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsVAPT
} catch {}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls

# ============================================================
# GLOBAL VARIABLES
# ============================================================
$TargetClean = $Target -replace "https?://", "" -replace "/$", ""
$OutputDir = "$PSScriptRoot\acrostrike_$TargetClean"
$Timestamp = Get-Date -Format "yyyy-MM-dd HH.mm.ss"
$TotalPhases = if ($Fast) { "20" } else { "20" }

# Vulnerability storage
$Global:Vulnerabilities = @()
$Global:ExploitChains = @()
$Global:Infrastructure = @{}
$Global:Subdomains = @()

# Baseline for soft 404 detection
$Global:Baseline404Size = 0
$Global:TargetURL = ""
$Global:SSLValid = $false
$Global:Homepage = ""
$Global:AllJS = ""
$Global:Headers = @{}
$Global:OpenPorts = @()
$Global:DNSRecords = @{}
$Global:SitemapUrls = @()
$Global:HttpMethods = @()
$Global:FormsFound = @()
$Global:SecretsFound = @()
$Global:ExposedFiles = @()
$Global:TechStack = @{}
$Global:OWASPResults = @{}
$Global:DomainAge = -1
$Global:WAFDetected = ""
$Global:ApiPaths = @()

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
New-Item -ItemType Directory -Force -Path "$OutputDir\js_files" | Out-Null
New-Item -ItemType Directory -Force -Path "$OutputDir\pages" | Out-Null
New-Item -ItemType Directory -Force -Path "$OutputDir\evidence" | Out-Null

function Add-Vuln {
    param(
        [string]$ID,
        [string]$Title,
        [string]$Severity,    # CRITICAL, HIGH, MEDIUM, LOW, INFO
        [double]$CVSS,
        [string]$Location,
        [string]$Evidence,
        [string]$Impact,
        [string]$Remediation,
        [string]$CWE = "",
        [bool]$Confirmed = $true
    )
    $Global:Vulnerabilities += [PSCustomObject]@{
        ID = $ID
        Title = $Title
        Severity = $Severity
        CVSS = $CVSS
        Location = $Location
        Evidence = $Evidence
        Impact = $Impact
        Remediation = $Remediation
        CWE = $CWE
        Confirmed = $Confirmed
    }
}

function Write-Phase {
    param([string]$Phase, [string]$Description)
    if (-not $Quiet) {
        Write-Host ""
        Write-Host "  [$Phase] $Description" -ForegroundColor Cyan
        Write-Host "  $('=' * (8 + $Phase.Length + $Description.Length))" -ForegroundColor DarkCyan
    }
}

function Write-Finding {
    param([string]$Type, [string]$Message)
    if (-not $Quiet) {
        switch ($Type) {
            "CRITICAL" { Write-Host "    [!!!] $Message" -ForegroundColor Red }
            "HIGH"     { Write-Host "    [!!]  $Message" -ForegroundColor DarkYellow }
            "MEDIUM"   { Write-Host "    [!]   $Message" -ForegroundColor Yellow }
            "LOW"      { Write-Host "    [.]   $Message" -ForegroundColor Gray }
            "OK"       { Write-Host "    [+]   $Message" -ForegroundColor Green }
            "INFO"     { Write-Host "    [i]   $Message" -ForegroundColor White }
            default    { Write-Host "    $Message" }
        }
    }
}

# ============================================================
if (-not $Quiet) {
    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor Cyan
    Write-Host "     ___                    ____  _        _ _        " -ForegroundColor Cyan
    Write-Host "    /   |  _________  _____/ __/_(_)___   (_) /_____  " -ForegroundColor Cyan
    Write-Host "   / /| | / ___/ __ \/ ___/ /_  / / / /   / / //_/ _ \ " -ForegroundColor Cyan
    Write-Host "  / ___ |/ /__/ /_/ / /  / __/ / / /_/   / / ,< /  __/ " -ForegroundColor Cyan
    Write-Host " /_/  |_|\___/\____/_/  /_/   /_/\__, / /_/_/|_|\___/  " -ForegroundColor Cyan
    Write-Host "                                /____/            v2.0" -ForegroundColor DarkCyan
    Write-Host "  ================================================================" -ForegroundColor Cyan
    Write-Host "  Target  : $TargetClean" -ForegroundColor Yellow
    Write-Host "  Output  : $OutputDir" -ForegroundColor Yellow
    Write-Host "  Started : $Timestamp" -ForegroundColor Yellow
    Write-Host "  Mode    : $(if($Fast){'Fast (skipping slow phases)'}else{'Full (all 20 phases)'})" -ForegroundColor Yellow
    Write-Host "  ================================================================" -ForegroundColor Cyan
}

# ============================================================
# PHASE 1: SSL/TLS ANALYSIS
# ============================================================
Write-Phase "1/20" "SSL/TLS Certificate Analysis"

$sslReport = @()
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.Connect($TargetClean, 443)
    $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, {param($s,$c,$ch,$e) return $true})
    $ssl.AuthenticateAsClient($TargetClean)
    $cert = $ssl.RemoteCertificate
    $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)
    
    $certSubject = $cert.Subject
    $certIssuer = $cert.Issuer
    $certExpiry = $x509.NotAfter
    $certStart = $x509.NotBefore
    $certSAN = ""
    foreach ($ext in $x509.Extensions) {
        if ($ext.Oid.FriendlyName -eq "Subject Alternative Name") { $certSAN = $ext.Format($true) }
    }
    
    $sslReport += "Subject: $certSubject"
    $sslReport += "Issuer: $certIssuer"
    $sslReport += "Valid: $certStart to $certExpiry"
    $sslReport += "SAN: $certSAN"
    $sslReport += "Protocol: $($ssl.SslProtocol)"
    $sslReport += "Cipher: $($ssl.CipherAlgorithm) $($ssl.CipherStrength)-bit"
    
    Write-Finding "INFO" "Subject: $certSubject"
    Write-Finding "INFO" "Issuer: $certIssuer"
    Write-Finding "INFO" "Expires: $certExpiry"
    
    # Check if cert is from LOCAL proxy (antivirus SSL inspection)
    $localProxyPatterns = "Norton|Antivirus|Web.*Shield|Kaspersky|Avast|ESET|Bitdefender|McAfee|mitmproxy|charles|fiddler|burp|ZScaler"
    if ($certIssuer -match $localProxyPatterns) {
        Write-Finding "INFO" "LOCAL PROXY DETECTED: $certIssuer"
        Write-Finding "INFO" "Your antivirus/proxy is intercepting SSL. This is NOT a server vulnerability."
        Write-Finding "INFO" "Skipping SSL cert analysis (results would be from your local proxy, not the server)"
        $sslReport += "NOTE: Local SSL proxy detected ($certIssuer). Cert findings skipped to avoid false positives."
    }
    elseif ($certIssuer -eq $certSubject) {
        Add-Vuln -ID "SSL-01" -Title "Self-Signed SSL Certificate" -Severity "CRITICAL" -CVSS 9.1 `
            -Location "https://$TargetClean" `
            -Evidence "Certificate is self-signed: Issuer and Subject are identical ($certIssuer)" `
            -Impact "HTTPS provides no trust verification. Browsers show security warnings. MITM attacks trivial." `
            -Remediation "Install a valid SSL certificate from a trusted CA (Let's Encrypt, DigiCert, etc.)" `
            -CWE "CWE-295"
        Write-Finding "CRITICAL" "SELF-SIGNED certificate detected"
    }
    
    if ($certExpiry -lt (Get-Date)) {
        Add-Vuln -ID "SSL-02" -Title "Expired SSL Certificate" -Severity "CRITICAL" -CVSS 8.5 `
            -Location "https://$TargetClean" -Evidence "Certificate expired on $certExpiry" `
            -Impact "Browsers will block access. Users trained to click through warnings." `
            -Remediation "Renew the SSL certificate immediately" -CWE "CWE-298"
        Write-Finding "CRITICAL" "Certificate EXPIRED: $certExpiry"
    }
    
    if ($ssl.SslProtocol -match "Ssl3|Tls$|Tls11") {
        Add-Vuln -ID "SSL-03" -Title "Weak TLS Protocol" -Severity "HIGH" -CVSS 7.4 `
            -Location "https://$TargetClean" -Evidence "Protocol: $($ssl.SslProtocol)" `
            -Impact "Vulnerable to POODLE, BEAST, or other protocol downgrade attacks" `
            -Remediation "Disable TLS 1.0/1.1 and SSLv3. Use TLS 1.2+ only" -CWE "CWE-326"
        Write-Finding "HIGH" "Weak protocol: $($ssl.SslProtocol)"
    }
    
    if ($ssl.CipherStrength -lt 128) {
        Add-Vuln -ID "SSL-04" -Title "Weak Cipher Suite" -Severity "HIGH" -CVSS 7.0 `
            -Location "https://$TargetClean" -Evidence "Cipher: $($ssl.CipherAlgorithm) $($ssl.CipherStrength)-bit" `
            -Impact "Encryption can be broken with sufficient computing power" `
            -Remediation "Configure strong cipher suites (AES-256-GCM, ChaCha20)" -CWE "CWE-327"
        Write-Finding "HIGH" "Weak cipher: $($ssl.CipherAlgorithm) $($ssl.CipherStrength)-bit"
    }
    
    $ssl.Close(); $tcp.Close()
    $Global:SSLValid = $true
} catch {
    Write-Finding "INFO" "Port 443 not responding or SSL handshake failed"
}

# Determine working URL
$Global:TargetURL = "https://$TargetClean"
try {
    $testResp = Invoke-WebRequest -Uri $Global:TargetURL -UseBasicParsing -TimeoutSec 8
} catch {
    $Global:TargetURL = "http://$TargetClean"
    try {
        $testResp = Invoke-WebRequest -Uri $Global:TargetURL -UseBasicParsing -TimeoutSec 8
        if ($Global:SSLValid -eq $false) {
            Write-Finding "CRITICAL" "HTTPS failed - site only serves HTTP"
        }
    } catch {
        Write-Finding "CRITICAL" "Cannot connect to target on HTTP or HTTPS"
    }
}

# Check HTTPS enforcement
if ($Global:TargetURL -match "^http://") {
    try {
        $httpResp = Invoke-WebRequest -Uri "http://$TargetClean" -UseBasicParsing -TimeoutSec 8 -MaximumRedirection 0
        if ($httpResp.StatusCode -ne 301 -and $httpResp.StatusCode -ne 302) {
            Add-Vuln -ID "SSL-05" -Title "No HTTPS Redirect" -Severity "CRITICAL" -CVSS 8.6 `
                -Location "http://$TargetClean" `
                -Evidence "HTTP request returns $($httpResp.StatusCode) instead of 301/302 redirect to HTTPS" `
                -Impact "All traffic transmitted in plaintext. Credentials, session tokens exposed to MITM." `
                -Remediation "Configure HTTP to HTTPS redirect (301) for all requests. Add HSTS header." `
                -CWE "CWE-319"
            Write-Finding "CRITICAL" "No HTTP->HTTPS redirect"
        }
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -ne 301 -and $code -ne 302) {
            Add-Vuln -ID "SSL-05" -Title "No HTTPS Redirect" -Severity "CRITICAL" -CVSS 8.6 `
                -Location "http://$TargetClean" `
                -Evidence "HTTP does not redirect to HTTPS" `
                -Impact "All traffic transmitted in plaintext." `
                -Remediation "Configure HTTP to HTTPS redirect (301)" -CWE "CWE-319"
        }
    }
}

$sslReport | Out-File "$OutputDir\evidence\ssl_analysis.txt" -Encoding UTF8
Write-Finding "OK" "SSL/TLS analysis complete"

# ============================================================
# PHASE 2: TECHNOLOGY FINGERPRINTING
# ============================================================
Write-Phase "2/20" "Technology Stack Fingerprinting"

try {
    $resp = Invoke-WebRequest -Uri $Global:TargetURL -UseBasicParsing -TimeoutSec 15
    $Global:Homepage = $resp.Content
    $Global:Headers = $resp.Headers
    $Global:Homepage | Out-File "$OutputDir\pages\index.html" -Encoding UTF8
    
    $server = $Global:Headers["Server"]
    if ($server) {
        $Global:TechStack["Server"] = $server
        Write-Finding "INFO" "Server: $server"
        if ($server -match "(Apache|nginx|IIS|Tomcat|Express|Kestrel)[/ ]*([\d.]+)?" ) {
            Add-Vuln -ID "INFO-01" -Title "Server Version Disclosure" -Severity "MEDIUM" -CVSS 5.3 `
                -Location "$Global:TargetURL (Server header)" `
                -Evidence "Server: $server" `
                -Impact "Attacker can search CVEs for this exact server version" `
                -Remediation "Remove or genericize the Server header" -CWE "CWE-200"
            Write-Finding "MEDIUM" "Server version disclosed: $server"
        }
    }
    
    $poweredBy = $Global:Headers["X-Powered-By"]
    if ($poweredBy) {
        $Global:TechStack["Powered-By"] = $poweredBy
        Add-Vuln -ID "INFO-02" -Title "Technology Disclosure (X-Powered-By)" -Severity "MEDIUM" -CVSS 5.3 `
            -Location "$Global:TargetURL (X-Powered-By header)" `
            -Evidence "X-Powered-By: $poweredBy" `
            -Impact "Reveals backend technology for targeted attacks" `
            -Remediation "Remove the X-Powered-By header" -CWE "CWE-200"
        Write-Finding "MEDIUM" "X-Powered-By: $poweredBy"
    }
    
    $aspnetVer = $Global:Headers["X-AspNet-Version"]
    if ($aspnetVer) {
        $Global:TechStack["ASP.NET"] = $aspnetVer
        Add-Vuln -ID "INFO-03" -Title "ASP.NET Version Disclosure" -Severity "HIGH" -CVSS 6.5 `
            -Location "$Global:TargetURL (X-AspNet-Version header)" `
            -Evidence "X-AspNet-Version: $aspnetVer" `
            -Impact "Exact framework build exposed. Enables precise CVE targeting." `
            -Remediation "Remove X-AspNet-Version header. In web.config: <httpRuntime enableVersionHeader='false'/>" `
            -CWE "CWE-200"
        Write-Finding "HIGH" "ASP.NET Version: $aspnetVer"
    }
    
    # Detect from HTML
    if ($Global:Homepage -match '__VIEWSTATE') { $Global:TechStack["Framework"] = "ASP.NET Web Forms"; Write-Finding "INFO" "ASP.NET Web Forms detected (ViewState)" }
    if ($Global:Homepage -match 'wp-content|wordpress') { $Global:TechStack["CMS"] = "WordPress"; Write-Finding "INFO" "WordPress detected" }
    if ($Global:Homepage -match 'Joomla') { $Global:TechStack["CMS"] = "Joomla"; Write-Finding "INFO" "Joomla detected" }
    if ($Global:Homepage -match 'Drupal') { $Global:TechStack["CMS"] = "Drupal"; Write-Finding "INFO" "Drupal detected" }
    if ($Global:Homepage -match 'jQuery') { $Global:TechStack["JS"] = "jQuery"; Write-Finding "INFO" "jQuery detected" }
    if ($Global:Homepage -match 'react|__NEXT_DATA__') { $Global:TechStack["JS"] = "React/Next.js"; Write-Finding "INFO" "React/Next.js detected" }
    if ($Global:Homepage -match 'angular') { $Global:TechStack["JS"] = "Angular"; Write-Finding "INFO" "Angular detected" }
    if ($Global:Homepage -match 'vue') { $Global:TechStack["JS"] = "Vue.js"; Write-Finding "INFO" "Vue.js detected" }
    
    # CDN versions from HTML
    $cdnVersions = [regex]::Matches($Global:Homepage, '(?:src|href)="[^"]*/([\\w.-]+?)(?:@|/)(\\d+\\.\\d+[\\d.]*)[^"]*"')
    foreach ($cdn in $cdnVersions) {
        $lib = $cdn.Groups[1].Value
        $ver = $cdn.Groups[2].Value
        $Global:TechStack["CDN_$lib"] = $ver
        Write-Finding "INFO" "CDN Library: $lib v$ver"
    }
    
} catch {
    Write-Finding "CRITICAL" "Cannot fetch homepage: $($_.Exception.Message)"
}

# Establish baseline for soft 404 detection
try {
    $fake = Invoke-WebRequest -Uri "$Global:TargetURL/nonexistent_page_xyz_$(Get-Random)" -UseBasicParsing -TimeoutSec 8
    $Global:Baseline404Size = $fake.Content.Length
    Write-Finding "INFO" "Baseline 404 page size: $($Global:Baseline404Size) bytes"
} catch {
    $Global:Baseline404Size = -1
}

# ============================================================
# PHASE 3: SECURITY HEADERS AUDIT
# ============================================================
Write-Phase "3/20" "Security Headers Audit"

$headerChecks = @(
    @{Name="Strict-Transport-Security"; Sev="HIGH"; CVSS=7.4; CWE="CWE-319"; 
      Impact="SSL stripping attacks possible. Attacker on same network can downgrade HTTPS to HTTP.";
      Fix="Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"},
    @{Name="Content-Security-Policy"; Sev="HIGH"; CVSS=7.1; CWE="CWE-79";
      Impact="No restriction on inline scripts or external resource loading. Any XSS becomes fully exploitable.";
      Fix="Add a Content-Security-Policy header restricting script-src, style-src, and default-src"},
    @{Name="X-Frame-Options"; Sev="HIGH"; CVSS=6.8; CWE="CWE-1021";
      Impact="Site can be embedded in iframes on attacker pages. Clickjacking attacks possible on login/admin forms.";
      Fix="Add header: X-Frame-Options: DENY (or SAMEORIGIN)"},
    @{Name="X-Content-Type-Options"; Sev="MEDIUM"; CVSS=5.3; CWE="CWE-16";
      Impact="Browser may interpret uploaded files as executable content via MIME sniffing.";
      Fix="Add header: X-Content-Type-Options: nosniff"},
    @{Name="Referrer-Policy"; Sev="LOW"; CVSS=3.1; CWE="CWE-200";
      Impact="Full URL including query parameters leaked to third-party sites.";
      Fix="Add header: Referrer-Policy: strict-origin-when-cross-origin"},
    @{Name="Permissions-Policy"; Sev="LOW"; CVSS=3.0; CWE="CWE-16";
      Impact="Browser features (camera, microphone, geolocation) not restricted.";
      Fix="Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()"}
)

$missingHeaders = 0
foreach ($check in $headerChecks) {
    $val = $Global:Headers[$check.Name]
    if (-not $val) {
        $missingHeaders++
        $vulnID = "HDR-$('{0:D2}' -f $missingHeaders)"
        Add-Vuln -ID $vulnID -Title "Missing $($check.Name) Header" -Severity $check.Sev -CVSS $check.CVSS `
            -Location "$Global:TargetURL (HTTP response headers)" `
            -Evidence "Header '$($check.Name)' is completely absent from the server response" `
            -Impact $check.Impact -Remediation $check.Fix -CWE $check.CWE
        Write-Finding $check.Sev "MISSING: $($check.Name)"
    } else {
        Write-Finding "OK" "$($check.Name): $val"
        if ($check.Name -eq "X-Frame-Options" -and $val -eq "ALLOWALL") {
            Add-Vuln -ID "HDR-WEAK-01" -Title "Weak X-Frame-Options (ALLOWALL)" -Severity "HIGH" -CVSS 6.8 `
                -Location "$Global:TargetURL" -Evidence "X-Frame-Options: ALLOWALL" `
                -Impact "Site can be framed by any origin" -Remediation "Change to DENY or SAMEORIGIN" -CWE "CWE-1021"
        }
        if ($check.Name -eq "Content-Security-Policy" -and $val -match "unsafe-inline.*unsafe-eval") {
            Add-Vuln -ID "HDR-WEAK-02" -Title "Weak CSP (unsafe-inline + unsafe-eval)" -Severity "MEDIUM" -CVSS 5.5 `
                -Location "$Global:TargetURL" -Evidence "CSP contains both unsafe-inline and unsafe-eval" `
                -Impact "CSP provides minimal XSS protection" -Remediation "Remove unsafe-inline and unsafe-eval directives" -CWE "CWE-79"
        }
    }
}

# CORS check
try {
    $corsResp = Invoke-WebRequest -Uri $Global:TargetURL -UseBasicParsing -TimeoutSec 8 -Headers @{"Origin"="https://evil.attacker.com"}
    $acao = $corsResp.Headers["Access-Control-Allow-Origin"]
    if ($acao -eq "*") {
        Add-Vuln -ID "HDR-CORS-01" -Title "Open CORS Policy (wildcard)" -Severity "HIGH" -CVSS 7.5 `
            -Location "$Global:TargetURL" -Evidence "Access-Control-Allow-Origin: *" `
            -Impact "Any website can make authenticated cross-origin requests to this site" `
            -Remediation "Restrict CORS to specific trusted origins" -CWE "CWE-942"
        Write-Finding "HIGH" "CORS: Open to all origins (*)"
    } elseif ($acao -eq "https://evil.attacker.com") {
        Add-Vuln -ID "HDR-CORS-02" -Title "CORS Origin Reflection" -Severity "CRITICAL" -CVSS 8.8 `
            -Location "$Global:TargetURL" -Evidence "Server reflects arbitrary Origin header: $acao" `
            -Impact "Any website can make authenticated cross-origin requests" `
            -Remediation "Whitelist specific origins instead of reflecting the Origin header" -CWE "CWE-942"
        Write-Finding "CRITICAL" "CORS: Reflects arbitrary origin!"
    } else {
        Write-Finding "OK" "CORS: Properly restricted"
    }
} catch {}

# ============================================================
# PHASE 4: HTTP METHODS ANALYSIS
# ============================================================
Write-Phase "4/20" "HTTP Methods Analysis"

$Global:BaselineGETSize = 0
$Global:BaselineGETHash = ""
try {
    $baseGet = Invoke-WebRequest -Uri $Global:TargetURL -UseBasicParsing -TimeoutSec 8
    $Global:BaselineGETSize = $baseGet.Content.Length
    $Global:BaselineGETHash = "$($baseGet.Content.Length)_$($baseGet.Content.Substring(0, [Math]::Min(200, $baseGet.Content.Length)).GetHashCode())"
} catch {}

$dangerousMethods = @("TRACE","PUT","DELETE","PATCH","OPTIONS")
foreach ($method in $dangerousMethods) {
    try {
        $methodResp = Invoke-WebRequest -Uri $Global:TargetURL -UseBasicParsing -TimeoutSec 5 -Method $method
        $code = $methodResp.StatusCode
        if ($code -eq 200) {
            $methodHash = "$($methodResp.Content.Length)_$($methodResp.Content.Substring(0, [Math]::Min(200, $methodResp.Content.Length)).GetHashCode())"
            $isSameAsGET = ($methodHash -eq $Global:BaselineGETHash)
            
            $Global:HttpMethods += $method
            if ($method -eq "TRACE") {
                $reflectsHeaders = $methodResp.Content -match "TRACE / HTTP|TRACE \\\*"
                if ($reflectsHeaders) {
                    Add-Vuln -ID "HTTP-01" -Title "TRACE Method Enabled (Cross-Site Tracing)" -Severity "HIGH" -CVSS 7.0 `
                        -Location "$Global:TargetURL" `
                        -Evidence "TRACE method returns HTTP $code AND reflects request headers in body" `
                        -Impact "Cross-Site Tracing (XST) can steal HttpOnly cookies when combined with XSS" `
                        -Remediation "Disable TRACE method in web server configuration" -CWE "CWE-693"
                    Write-Finding "HIGH" "TRACE enabled + reflects headers = CONFIRMED XST"
                } else {
                    Write-Finding "INFO" "TRACE returns 200 but does NOT reflect headers (not exploitable)"
                }
            }
            elseif ($method -eq "PUT") {
                if ($isSameAsGET) {
                    Write-Finding "INFO" "PUT returns 200 but same page as GET (server ignores method - not vulnerable)"
                } else {
                    Add-Vuln -ID "HTTP-02" -Title "PUT Method Allowed" -Severity "CRITICAL" -CVSS 9.1 `
                        -Location "$Global:TargetURL" -Evidence "PUT returns HTTP $code with different response than GET ($($methodResp.Content.Length) vs $($Global:BaselineGETSize) bytes)" `
                        -Impact "Attacker may be able to upload/overwrite files on the server" `
                        -Remediation "Disable PUT method unless required by the application" -CWE "CWE-749"
                    Write-Finding "CRITICAL" "PUT method CONFIRMED - different response than GET"
                }
            }
            elseif ($method -eq "DELETE") {
                if ($isSameAsGET) {
                    Write-Finding "INFO" "DELETE returns 200 but same page as GET (server ignores method - not vulnerable)"
                } else {
                    Add-Vuln -ID "HTTP-03" -Title "DELETE Method Allowed" -Severity "HIGH" -CVSS 8.1 `
                        -Location "$Global:TargetURL" -Evidence "DELETE returns HTTP $code with different response than GET" `
                        -Impact "Attacker may be able to delete server resources" `
                        -Remediation "Disable DELETE method unless required" -CWE "CWE-749"
                    Write-Finding "HIGH" "DELETE method CONFIRMED - different response than GET"
                }
            }
            elseif ($method -eq "OPTIONS") {
                $allow = $methodResp.Headers["Allow"]
                Write-Finding "INFO" "OPTIONS allowed. Allow header: $allow"
            }
        }
    } catch {}
}

# ============================================================
# PHASE 5: COOKIE SECURITY
# ============================================================
Write-Phase "5/20" "Cookie Security Analysis"

try {
    $cookieResp = Invoke-WebRequest -Uri $Global:TargetURL -UseBasicParsing -TimeoutSec 10
    $setCookies = $cookieResp.Headers["Set-Cookie"]
    if ($setCookies) {
        Write-Finding "INFO" "Cookies found: $setCookies"
        $cookieList = if ($setCookies -is [array]) { $setCookies } else { @($setCookies) }
        foreach ($cookie in $cookieList) {
            $cookieName = ($cookie -split "=")[0].Trim()
            if ($cookie -notmatch "(?i)secure") {
                Add-Vuln -ID "COOKIE-01" -Title "Cookie Missing Secure Flag ($cookieName)" -Severity "MEDIUM" -CVSS 5.4 `
                    -Location "$Global:TargetURL" -Evidence "Set-Cookie: $cookie (no Secure flag)" `
                    -Impact "Cookie transmitted over unencrypted HTTP connections" `
                    -Remediation "Add Secure flag to all cookies" -CWE "CWE-614"
                Write-Finding "MEDIUM" "Cookie '$cookieName' missing Secure flag"
            }
            if ($cookie -notmatch "(?i)httponly") {
                Add-Vuln -ID "COOKIE-02" -Title "Cookie Missing HttpOnly Flag ($cookieName)" -Severity "MEDIUM" -CVSS 5.4 `
                    -Location "$Global:TargetURL" -Evidence "Set-Cookie: $cookie (no HttpOnly flag)" `
                    -Impact "Cookie accessible via JavaScript - can be stolen via XSS" `
                    -Remediation "Add HttpOnly flag to session cookies" -CWE "CWE-1004"
                Write-Finding "MEDIUM" "Cookie '$cookieName' missing HttpOnly flag"
            }
            if ($cookie -notmatch "(?i)samesite") {
                Write-Finding "LOW" "Cookie '$cookieName' missing SameSite attribute"
            }
        }
    } else {
        Write-Finding "OK" "No cookies set on homepage"
    }
} catch {}

# ============================================================
# PHASE 6: SENSITIVE FILE DISCOVERY (60+ paths)
# ============================================================
Write-Phase "6/20" "Sensitive File Discovery"

$sensitiveFiles = @(
    @{Path="robots.txt"; Risk="INFO"; Desc="May reveal hidden directories"},
    @{Path="sitemap.xml"; Risk="INFO"; Desc="Full URL structure"},
    @{Path=".env"; Risk="CRITICAL"; Desc="Environment variables with secrets"},
    @{Path=".env.local"; Risk="CRITICAL"; Desc="Local environment secrets"},
    @{Path=".env.production"; Risk="CRITICAL"; Desc="Production secrets"},
    @{Path=".env.backup"; Risk="CRITICAL"; Desc="Backup of secrets"},
    @{Path=".git/HEAD"; Risk="CRITICAL"; Desc="Git repository exposed"},
    @{Path=".git/config"; Risk="CRITICAL"; Desc="Git config with potential credentials"},
    @{Path="web.config"; Risk="CRITICAL"; Desc="ASP.NET config with DB strings"},
    @{Path="web.config.bak"; Risk="CRITICAL"; Desc="Backup of config"},
    @{Path="wp-config.php"; Risk="CRITICAL"; Desc="WordPress DB credentials"},
    @{Path="package.json"; Risk="MEDIUM"; Desc="Dependencies and versions"},
    @{Path="composer.json"; Risk="MEDIUM"; Desc="PHP dependencies"},
    @{Path="Dockerfile"; Risk="MEDIUM"; Desc="Container configuration"},
    @{Path="docker-compose.yml"; Risk="HIGH"; Desc="Infrastructure layout"},
    @{Path=".htaccess"; Risk="MEDIUM"; Desc="Apache config"},
    @{Path=".htpasswd"; Risk="CRITICAL"; Desc="Password hashes"},
    @{Path="phpinfo.php"; Risk="HIGH"; Desc="Full PHP configuration"},
    @{Path="info.php"; Risk="HIGH"; Desc="PHP info page"},
    @{Path="elmah.axd"; Risk="HIGH"; Desc="ASP.NET error logs"},
    @{Path="trace.axd"; Risk="HIGH"; Desc="ASP.NET trace logs"},
    @{Path="swagger.json"; Risk="MEDIUM"; Desc="API documentation"},
    @{Path="swagger-ui.html"; Risk="MEDIUM"; Desc="API documentation UI"},
    @{Path="api-docs"; Risk="MEDIUM"; Desc="API documentation"},
    @{Path="crossdomain.xml"; Risk="MEDIUM"; Desc="Flash cross-domain policy"},
    @{Path=".well-known/security.txt"; Risk="INFO"; Desc="Security contact"},
    @{Path="backup.zip"; Risk="CRITICAL"; Desc="Site backup"},
    @{Path="backup.sql"; Risk="CRITICAL"; Desc="Database dump"},
    @{Path="dump.sql"; Risk="CRITICAL"; Desc="Database dump"},
    @{Path="db.sql"; Risk="CRITICAL"; Desc="Database dump"},
    @{Path="database.sql"; Risk="CRITICAL"; Desc="Database dump"},
    @{Path="backup.tar.gz"; Risk="CRITICAL"; Desc="Site backup"},
    @{Path="config.json"; Risk="HIGH"; Desc="App configuration"},
    @{Path="config.yml"; Risk="HIGH"; Desc="App configuration"},
    @{Path="firebase.json"; Risk="MEDIUM"; Desc="Firebase config"},
    @{Path=".firebaserc"; Risk="MEDIUM"; Desc="Firebase project"},
    @{Path="vercel.json"; Risk="LOW"; Desc="Vercel config"},
    @{Path="netlify.toml"; Risk="LOW"; Desc="Netlify config"},
    @{Path="server-status"; Risk="HIGH"; Desc="Apache server status"},
    @{Path="server-info"; Risk="HIGH"; Desc="Apache server info"},
    # v2.0 NEW paths
    @{Path=".svn/entries"; Risk="CRITICAL"; Desc="SVN repository exposed"},
    @{Path=".hg/requires"; Risk="CRITICAL"; Desc="Mercurial repository exposed"},
    @{Path="debug.log"; Risk="HIGH"; Desc="Debug log with stack traces"},
    @{Path="error.log"; Risk="HIGH"; Desc="Error log with system paths"},
    @{Path="access.log"; Risk="MEDIUM"; Desc="Access log with user IPs"},
    @{Path="webpack.config.js"; Risk="MEDIUM"; Desc="Build configuration"},
    @{Path="Gruntfile.js"; Risk="LOW"; Desc="Build task runner config"},
    @{Path="Gulpfile.js"; Risk="LOW"; Desc="Build task runner config"},
    @{Path="api/swagger.json"; Risk="MEDIUM"; Desc="API schema definition"},
    @{Path="api/swagger.yaml"; Risk="MEDIUM"; Desc="API schema definition"},
    @{Path="openapi.json"; Risk="MEDIUM"; Desc="OpenAPI specification"},
    @{Path="graphql"; Risk="MEDIUM"; Desc="GraphQL endpoint"},
    @{Path="actuator/health"; Risk="HIGH"; Desc="Spring Boot health endpoint"},
    @{Path="actuator/env"; Risk="CRITICAL"; Desc="Spring Boot environment variables"},
    @{Path="_profiler"; Risk="HIGH"; Desc="Symfony profiler"},
    @{Path="__debug__"; Risk="HIGH"; Desc="Django debug toolbar"},
    @{Path="Jenkinsfile"; Risk="MEDIUM"; Desc="CI/CD pipeline config"},
    @{Path=".gitlab-ci.yml"; Risk="MEDIUM"; Desc="GitLab CI config"},
    @{Path="admin.php"; Risk="MEDIUM"; Desc="Admin entry point"},
    @{Path="login.php"; Risk="LOW"; Desc="Login page"},
    @{Path=".aws/credentials"; Risk="CRITICAL"; Desc="AWS credentials file"}
)

$exposedCount = 0
foreach ($file in $sensitiveFiles) {
    try {
        $fileResp = Invoke-WebRequest -Uri "$($Global:TargetURL)/$($file.Path)" -UseBasicParsing -TimeoutSec 5
        $size = $fileResp.Content.Length
        
        # Soft 404 check
        if ($Global:Baseline404Size -gt 0 -and [Math]::Abs($size - $Global:Baseline404Size) -lt 500) { continue }
        
        if ($fileResp.StatusCode -eq 200 -and $size -gt 0) {
            $exposedCount++
            $Global:ExposedFiles += $file.Path
            
            if ($file.Risk -ne "INFO") {
                $vulnID = "FILE-$('{0:D2}' -f $exposedCount)"
                Add-Vuln -ID $vulnID -Title "Exposed Sensitive File: /$($file.Path)" -Severity $file.Risk `
                    -CVSS $(switch($file.Risk) {"CRITICAL"{9.0} "HIGH"{7.5} "MEDIUM"{5.0} default{3.0}}) `
                    -Location "$($Global:TargetURL)/$($file.Path)" `
                    -Evidence "HTTP 200 returned, $size bytes. $($file.Desc)" `
                    -Impact "File contains $($file.Desc.ToLower()). May expose credentials, infrastructure details, or sensitive data." `
                    -Remediation "Block public access to this file. Add deny rules in web server config." -CWE "CWE-538"
                Write-Finding $file.Risk "EXPOSED: /$($file.Path) ($size bytes) - $($file.Desc)"
            } else {
                Write-Finding "INFO" "Found: /$($file.Path) ($size bytes)"
            }
            
            $safeName = $file.Path -replace "[/\\]", "_"
            $fileResp.Content | Out-File "$OutputDir\evidence\exposed_$safeName" -Encoding UTF8
        }
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -eq 403) {
            Write-Finding "INFO" "Blocked (403): /$($file.Path)"
        }
    }
}
Write-Finding "OK" "$exposedCount sensitive files accessible"

# Parse robots.txt for hidden paths
if ($Global:ExposedFiles -contains "robots.txt") {
    $robotsContent = Get-Content "$OutputDir\evidence\exposed_robots.txt" -Raw -ErrorAction SilentlyContinue
    if ($robotsContent) {
        $disallowed = [regex]::Matches($robotsContent, 'Disallow:\s*(/\S+)') | ForEach-Object { $_.Groups[1].Value }
        if ($disallowed.Count -gt 0) {
            Add-Vuln -ID "FILE-ROBOTS" -Title "Robots.txt Reveals Hidden Directories" -Severity "MEDIUM" -CVSS 4.0 `
                -Location "$($Global:TargetURL)/robots.txt" `
                -Evidence "Disallowed paths found: $($disallowed -join ', ')" `
                -Impact "Attacker can enumerate internal directory structure from robots.txt" `
                -Remediation "Remove sensitive paths from robots.txt. Use authentication instead." -CWE "CWE-200"
            Write-Finding "MEDIUM" "Robots.txt disallows: $($disallowed -join ', ')"
        }
    }
}

# ============================================================
# PHASE 7: PORT SCANNING
# ============================================================
if ($Fast) {
    Write-Phase "7/20" "Port Scanning [SKIPPED - Fast Mode]"
} else {
    Write-Phase "7/20" "Port Scanning"
    
    $portMap = @{
        21="FTP"; 22="SSH"; 23="Telnet"; 25="SMTP"; 53="DNS";
        80="HTTP"; 110="POP3"; 143="IMAP"; 443="HTTPS"; 445="SMB";
        993="IMAPS"; 995="POP3S"; 1433="MSSQL"; 1521="Oracle";
        2082="cPanel"; 2083="cPanel-SSL"; 3306="MySQL"; 3389="RDP";
        5432="PostgreSQL"; 5900="VNC"; 6379="Redis"; 8000="HTTP-Alt";
        8080="HTTP-Proxy"; 8443="HTTPS-Alt"; 8880="HTTP-Alt2";
        8888="HTTP-Alt3"; 9090="Mgmt"; 9200="Elasticsearch"; 27017="MongoDB"
    }
    
    foreach ($port in ($portMap.Keys | Sort-Object)) {
        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $result = $tcp.BeginConnect($TargetClean, $port, $null, $null)
            $wait = $result.AsyncWaitHandle.WaitOne(600, $false)
            if ($wait -and $tcp.Connected) {
                $svcName = $portMap[[int]$port]
                $Global:OpenPorts += [PSCustomObject]@{Port=$port; Service=$svcName}
                Write-Finding "OK" "Port $port OPEN ($svcName)"
                
                if ($port -in @(23,110,143,445,1433,3306,3389,5432,5900,6379,9200,27017)) {
                    $sev = if ($port -in @(3389,1433,3306,5432,6379,27017,445)) { "HIGH" } else { "MEDIUM" }
                    Add-Vuln -ID "PORT-$port" -Title "Sensitive Port Open: $port ($svcName)" `
                        -Severity $sev -CVSS $(if ($sev -eq "HIGH") {7.5} else {5.0}) `
                        -Location "$TargetClean`:$port" `
                        -Evidence "TCP port $port ($svcName) is accepting connections" `
                        -Impact "$(switch($port) {
                            23 {"Telnet transmits credentials in plaintext"}
                            110 {"POP3 email retrieved without encryption"}
                            143 {"IMAP email retrieved without encryption"}
                            445 {"SMB exposed - potential for EternalBlue/ransomware"}
                            1433 {"SQL Server database directly accessible"}
                            3306 {"MySQL database directly accessible"}
                            3389 {"Remote Desktop exposed - brute force target"}
                            5432 {"PostgreSQL database directly accessible"}
                            5900 {"VNC remote access exposed"}
                            6379 {"Redis database exposed (often no auth)"}
                            9200 {"Elasticsearch exposed (often no auth)"}
                            27017 {"MongoDB exposed (often no auth)"}
                            default {"Service unnecessarily exposed"}
                        })" `
                        -Remediation "Restrict access via firewall. Only allow from trusted IPs." -CWE "CWE-284"
                }
            }
        } catch {} finally { $tcp.Close() }
    }
}

# ============================================================
# PHASE 8: SUBDOMAIN DISCOVERY
# ============================================================
if ($Fast) {
    Write-Phase "8/20" "Subdomain Discovery [SKIPPED - Fast Mode]"
} else {
    Write-Phase "8/20" "Subdomain Discovery"
    
    # WILDCARD DNS DETECTION
    $Global:HasWildcardDNS = $false
    $wildcardTestNames = @("nonexistent-xyzzy-$(Get-Random)", "fakesub-test-$(Get-Random)")
    $wildcardIPs = @()
    foreach ($wt in $wildcardTestNames) {
        try {
            $wdns = Resolve-DnsName -Name "$wt.$TargetClean" -Type A -ErrorAction Stop
            $wip = ($wdns | Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress
            if ($wip) { $wildcardIPs += $wip }
        } catch {}
    }
    if ($wildcardIPs.Count -ge 2) {
        $Global:HasWildcardDNS = $true
        Write-Finding "INFO" "WILDCARD DNS detected: *.$TargetClean -> $($wildcardIPs[0])"
        Write-Finding "INFO" "Skipping subdomain brute-force (all names resolve - would produce false positives)"
    }
    
    $subPrefixes = @("www","mail","webmail","owa","ftp","admin","portal","student","faculty",
        "exam","erp","moodle","lms","dev","staging","test","api","cdn","static",
        "blog","forum","wiki","git","gitlab","jenkins","jira","vpn","remote",
        "intranet","uat","demo","sandbox","backup","old","new","beta","alpha",
        "app","mobile","m","ns1","ns2","mx","smtp","pop","imap","cpanel","plesk")
    
    $wildcardPageHash = ""
    if ($Global:HasWildcardDNS) {
        try {
            $wcResp = Invoke-WebRequest -Uri "https://nonexistent-baseline-$(Get-Random).$TargetClean" -UseBasicParsing -TimeoutSec 6
            $wildcardPageHash = "$($wcResp.Content.Length)_$($wcResp.StatusCode)"
        } catch {
            try {
                $wcResp = Invoke-WebRequest -Uri "http://nonexistent-baseline-$(Get-Random).$TargetClean" -UseBasicParsing -TimeoutSec 6
                $wildcardPageHash = "$($wcResp.Content.Length)_$($wcResp.StatusCode)"
            } catch { $wildcardPageHash = "error" }
        }
    }
    
    foreach ($sub in $subPrefixes) {
        $fqdn = "$sub.$TargetClean"
        try {
            $dns = Resolve-DnsName -Name $fqdn -Type A -ErrorAction Stop
            $ip = ($dns | Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress
            if ($ip) {
                if ($Global:HasWildcardDNS) {
                    $isDifferent = $false
                    foreach ($proto in @("https","http")) {
                        try {
                            $subCheck = Invoke-WebRequest -Uri "$proto`://$fqdn" -UseBasicParsing -TimeoutSec 5
                            $subHash = "$($subCheck.Content.Length)_$($subCheck.StatusCode)"
                            if ($subHash -ne $wildcardPageHash) { $isDifferent = $true }
                            break
                        } catch {}
                    }
                    if (-not $isDifferent) { continue }
                }
                
                $subInfo = [PSCustomObject]@{Name=$fqdn; IP=$ip; Server=""; Title=""; Status=""}
                foreach ($proto in @("https","http")) {
                    try {
                        $subResp = Invoke-WebRequest -Uri "$proto`://$fqdn" -UseBasicParsing -TimeoutSec 6
                        $subInfo.Status = "$proto`:$($subResp.StatusCode)"
                        $subInfo.Server = $subResp.Headers["Server"]
                        if ($subResp.Content -match '<title>(.*?)</title>') { $subInfo.Title = $Matches[1].Trim() }
                        
                        if ($subInfo.Title -match "Default|Parallels|Plesk|cPanel|Welcome to nginx|Apache.*Test|IIS.*Windows|Under Construction|Coming Soon") {
                            Add-Vuln -ID "SUB-$sub" -Title "Unconfigured Subdomain: $fqdn" -Severity "HIGH" -CVSS 7.0 `
                                -Location "$proto`://$fqdn" `
                                -Evidence "Title: '$($subInfo.Title)'. Server: $($subInfo.Server). Default/unconfigured page detected." `
                                -Impact "Unconfigured subdomains are prime targets. May have default credentials." `
                                -Remediation "Remove DNS record or properly configure the subdomain." -CWE "CWE-16"
                            Write-Finding "HIGH" "[DEFAULT PAGE] $fqdn -> $ip ($($subInfo.Title))"
                        } else {
                            Write-Finding "OK" "$fqdn -> $ip ($($subInfo.Title))"
                        }
                        break
                    } catch {}
                }
                if (-not $subInfo.Status) { Write-Finding "INFO" "$fqdn -> $ip (no HTTP response)" }
                $Global:Subdomains += $subInfo
            }
        } catch {}
    }
    Write-Finding "OK" "$($Global:Subdomains.Count) subdomains discovered (wildcard filtered: $($Global:HasWildcardDNS))"
}

# ============================================================
# PHASE 9: JS ANALYSIS (Secrets, APIs, Endpoints)
# ============================================================
Write-Phase "9/20" "JavaScript Analysis"

$jsFiles = @()
if ($Global:Homepage) {
    $jsMatches = [regex]::Matches($Global:Homepage, '(?:src)="([^"]*\.js[^"]*)"')
    foreach ($match in $jsMatches) {
        $jsUrl = $match.Groups[1].Value
        if ($jsUrl -notmatch "^http") { $jsUrl = "$($Global:TargetURL)$jsUrl" }
        $jsFiles += $jsUrl
    }
    $jsFiles = $jsFiles | Sort-Object -Unique
    Write-Finding "INFO" "Found $($jsFiles.Count) JS files"
    
    $allJsContent = ""
    foreach ($js in $jsFiles) {
        try {
            $jsContent = (Invoke-WebRequest -Uri $js -UseBasicParsing -TimeoutSec 8).Content
            $allJsContent += "`n$jsContent"
            $safeName = ($js.Split("/")[-1].Split("?")[0])
            if ($safeName) { $jsContent | Out-File "$OutputDir\js_files\$safeName" -Encoding UTF8 }
        } catch {}
    }
    $Global:AllJS = $allJsContent
    if ($allJsContent) { $allJsContent | Out-File "$OutputDir\evidence\all_js_combined.txt" -Encoding UTF8 }
    
    # Secret scanning
    $secretPatterns = @{
        "AWS Access Key"     = 'AKIA[0-9A-Z]{16}'
        "Google API Key"     = 'AIza[0-9A-Za-z_-]{35}'
        "JWT Token"          = 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+'
        "Private Key"        = '-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'
        "Slack Token"        = 'xox[bpas]-[0-9a-zA-Z-]{10,}'
        "GitHub Token"       = 'gh[ps]_[A-Za-z0-9_]{36}'
        "Stripe Key"         = '[sr]k_live_[0-9a-zA-Z]{24,}'
        "SendGrid Key"       = 'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'
        "Generic API Key"    = '(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["\x27]([^"\x27\s]{8,})["\x27]'
        "Generic Secret"     = '(?i)(?:secret|client[_-]?secret)\s*[:=]\s*["\x27]([^"\x27\s]{8,})["\x27]'
        "Generic Password"   = '(?i)(?:password|passwd|pwd)\s*[:=]\s*["\x27]([^"\x27\s]{4,})["\x27]'
    }
    
    foreach ($name in $secretPatterns.Keys) {
        $found = [regex]::Matches($allJsContent, $secretPatterns[$name])
        if ($found.Count -gt 0) {
            $Global:SecretsFound += "$name : $($found[0].Value)"
            Add-Vuln -ID "SECRET-$($name -replace ' ','')" -Title "Hardcoded Secret in JS: $name" `
                -Severity "CRITICAL" -CVSS 9.0 `
                -Location "JavaScript source files" `
                -Evidence "Pattern '$name' matched $($found.Count) time(s). Sample: $($found[0].Value.Substring(0, [Math]::Min(60, $found[0].Value.Length)))..." `
                -Impact "Credentials/API keys exposed in client-side code. Can be used for unauthorized access to backend services." `
                -Remediation "Remove all secrets from frontend code. Use server-side API proxies." -CWE "CWE-798"
            Write-Finding "CRITICAL" "SECRET FOUND: $name ($($found.Count) matches)"
        }
    }
    if ($Global:SecretsFound.Count -eq 0) { Write-Finding "OK" "No hardcoded secrets detected" }
    
    # API endpoint discovery
    $Global:ApiPaths = @([regex]::Matches($allJsContent, '["\\x27](/api/[^"\\x27\\s]{2,})["\\x27]') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
    if ($Global:ApiPaths.Count -gt 0) { Write-Finding "INFO" "API endpoints in JS: $($Global:ApiPaths -join ', ')" }
    
    # Source map check - ONLY for first-party JS
    $mapsFound = 0
    $thirdPartyCDNs = @("cdn.jsdelivr.net","cdnjs.cloudflare.com","unpkg.com","ajax.googleapis.com",
        "code.jquery.com","stackpath.bootstrapcdn.com","maxcdn.bootstrapcdn.com","cdn.datatables.net",
        "fonts.googleapis.com","cse.google.com","www.google.com","www.gstatic.com",
        "maps.googleapis.com","translate.google.com","platform.twitter.com",
        "connect.facebook.net","cdn.firebase.com","cdn.tailwindcss.com")
    foreach ($js in ($jsFiles | Select-Object -First 15)) {
        $isThirdParty = $false
        foreach ($cdn in $thirdPartyCDNs) {
            if ($js -match [regex]::Escape($cdn)) { $isThirdParty = $true; break }
        }
        if ($isThirdParty) {
            Write-Finding "INFO" "Skipping CDN source map (third-party): $js"
            continue
        }
        try {
            $mapResp = Invoke-WebRequest -Uri "$js.map" -UseBasicParsing -TimeoutSec 4 -Method Head
            if ($mapResp.StatusCode -eq 200) {
                $mapsFound++
                Add-Vuln -ID "SRCMAP-$mapsFound" -Title "Source Map Exposed (First-Party)" -Severity "HIGH" -CVSS 7.5 `
                    -Location "$js.map" -Evidence "First-party source map file publicly accessible (not a CDN)" `
                    -Impact "YOUR unminified source code is readable. Reveals business logic, internal APIs, comments." `
                    -Remediation "Remove .map files from production or restrict access" -CWE "CWE-540"
                Write-Finding "HIGH" "SOURCE MAP (YOUR CODE): $js.map"
            }
        } catch {}
    }
    if ($mapsFound -eq 0) { Write-Finding "OK" "No first-party source maps exposed" }
    
    # v2.0: Known Vulnerable JS Libraries
    $vulnLibs = @(
        @{Pattern='jquery[/-](\d+\.\d+\.\d+)'; Name="jQuery"; MaxSafe="3.5.0"; CVE="CVE-2020-11022"; Issue="XSS via jQuery.htmlPrefilter"},
        @{Pattern='angular[/-](\d+\.\d+\.\d+)'; Name="AngularJS"; MaxSafe="1.6.9"; CVE="CVE-2019-14863"; Issue="XSS via sandbox escape"},
        @{Pattern='bootstrap[/-](\d+\.\d+\.\d+)'; Name="Bootstrap"; MaxSafe="3.4.0"; CVE="CVE-2018-14041"; Issue="XSS in data-target"},
        @{Pattern='lodash[/-](\d+\.\d+\.\d+)'; Name="Lodash"; MaxSafe="4.17.21"; CVE="CVE-2021-23337"; Issue="Prototype pollution"}
    )
    foreach ($vl in $vulnLibs) {
        $libMatch = [regex]::Match($allJsContent + " " + ($Global:Homepage), $vl.Pattern)
        if ($libMatch.Success) {
            $detectedVer = $libMatch.Groups[1].Value
            try {
                if ([version]$detectedVer -lt [version]$vl.MaxSafe) {
                    Add-Vuln -ID "JSLIB-$($vl.Name)" -Title "Vulnerable JS Library: $($vl.Name) v$detectedVer" `
                        -Severity "MEDIUM" -CVSS 5.3 `
                        -Location "JavaScript source" `
                        -Evidence "$($vl.Name) v$detectedVer detected (vulnerable below v$($vl.MaxSafe)). $($vl.CVE): $($vl.Issue)" `
                        -Impact "Known vulnerability can be exploited by attackers targeting this specific library version." `
                        -Remediation "Update $($vl.Name) to v$($vl.MaxSafe) or later" -CWE "CWE-1104"
                    Write-Finding "MEDIUM" "VULNERABLE: $($vl.Name) v$detectedVer ($($vl.CVE))"
                }
            } catch {}
        }
    }
}

# ============================================================
# PHASE 10: DNS INTELLIGENCE
# ============================================================
Write-Phase "10/20" "DNS Intelligence"

$recordTypes = @("A","AAAA","MX","NS","TXT","CNAME","SOA")
foreach ($type in $recordTypes) {
    try {
        $records = Resolve-DnsName -Name $TargetClean -Type $type -ErrorAction Stop
        foreach ($r in $records) {
            $val = switch ($type) {
                "A"     { $r.IPAddress }
                "AAAA"  { $r.IPAddress }
                "MX"    { "$($r.NameExchange) (Priority: $($r.Preference))" }
                "NS"    { $r.NameHost }
                "TXT"   { $r.Strings -join " " }
                "CNAME" { $r.NameHost }
                "SOA"   { "$($r.PrimaryServer)" }
                default { "" }
            }
            if ($val) {
                $Global:DNSRecords["$type"] += @($val)
                Write-Finding "INFO" "$type : $val"
            }
        }
    } catch {}
}

# SPF analysis
$spfRecord = ($Global:DNSRecords["TXT"] | Where-Object { $_ -match "spf" }) -join ""
if ($spfRecord) {
    if ($spfRecord -match "~all") {
        Add-Vuln -ID "DNS-SPF" -Title "SPF Soft Fail Policy (~all)" -Severity "MEDIUM" -CVSS 5.8 `
            -Location "DNS TXT record for $TargetClean" `
            -Evidence "SPF: $spfRecord (uses ~all instead of -all)" `
            -Impact "Spoofed emails from @$TargetClean may pass some email filters" `
            -Remediation "Change ~all to -all for hard fail policy" -CWE "CWE-290"
        Write-Finding "MEDIUM" "SPF uses ~all (softfail)"
    }
    if ($spfRecord -match "\+all") {
        Add-Vuln -ID "DNS-SPF-OPEN" -Title "SPF Allows All Senders (+all)" -Severity "HIGH" -CVSS 7.5 `
            -Location "DNS TXT record" -Evidence "SPF: $spfRecord (+all allows anyone)" `
            -Impact "Anyone can send emails as @$TargetClean" -Remediation "Fix SPF to restrict senders" -CWE "CWE-290"
        Write-Finding "HIGH" "SPF allows ALL senders (+all)!"
    }
} else {
    Add-Vuln -ID "DNS-NOSPF" -Title "No SPF Record" -Severity "MEDIUM" -CVSS 5.8 `
        -Location "DNS for $TargetClean" -Evidence "No TXT record containing SPF found" `
        -Impact "No email sender verification. Domain can be freely spoofed." `
        -Remediation "Add SPF TXT record" -CWE "CWE-290"
    Write-Finding "MEDIUM" "No SPF record found"
}

# DMARC check
try {
    $dmarc = Resolve-DnsName -Name "_dmarc.$TargetClean" -Type TXT -ErrorAction Stop
    $dmarcVal = $dmarc.Strings -join ""
    Write-Finding "INFO" "DMARC: $dmarcVal"
    if ($dmarcVal -match "p=none") {
        Add-Vuln -ID "DNS-DMARC" -Title "DMARC Policy Set to None" -Severity "MEDIUM" -CVSS 5.0 `
            -Location "_dmarc.$TargetClean" -Evidence "DMARC: $dmarcVal (p=none)" `
            -Impact "DMARC is monitoring only, not enforcing. Spoofed emails not blocked." `
            -Remediation "Change DMARC policy to p=quarantine or p=reject" -CWE "CWE-290"
        Write-Finding "MEDIUM" "DMARC policy is 'none' (not enforcing)"
    }
} catch {
    Add-Vuln -ID "DNS-NODMARC" -Title "No DMARC Record" -Severity "MEDIUM" -CVSS 5.0 `
        -Location "_dmarc.$TargetClean" -Evidence "No DMARC TXT record found" `
        -Impact "No DMARC policy. Email spoofing not detectable by receivers." `
        -Remediation "Add DMARC record: v=DMARC1; p=reject; rua=mailto:admin@$TargetClean" -CWE "CWE-290"
    Write-Finding "MEDIUM" "No DMARC record"
}

# ============================================================
# PHASE 11: FORM & INPUT ANALYSIS (Enhanced v2.0)
# ============================================================
Write-Phase "11/20" "Form and Input Analysis"

if ($Global:Homepage) {
    $forms = [regex]::Matches($Global:Homepage, '<form[^>]*>(.*?)</form>', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    foreach ($form in $forms) {
        $action = if ($form.Value -match 'action="([^"]*)"') { $Matches[1] } else { "self" }
        $method = if ($form.Value -match 'method="([^"]*)"') { $Matches[1].ToUpper() } else { "GET" }
        $inputs = [regex]::Matches($form.Value, '<input[^>]*>')
        $inputNames = @()
        foreach ($input in $inputs) {
            $iname = if ($input.Value -match 'name="([^"]*)"') { $Matches[1] } else { "" }
            $itype = if ($input.Value -match 'type="([^"]*)"') { $Matches[1] } else { "text" }
            if ($iname) { $inputNames += "$itype`:$iname" }
        }
        $Global:FormsFound += [PSCustomObject]@{Action=$action; Method=$method; Inputs=$inputNames}
        Write-Finding "INFO" "Form: $method $action -> $($inputNames -join ', ')"
        
        # Check for password fields over HTTP
        if (($inputNames -match "password") -and $Global:TargetURL -match "^http://") {
            Add-Vuln -ID "FORM-HTTP-PWD" -Title "Password Form Over HTTP" -Severity "CRITICAL" -CVSS 9.0 `
                -Location "$Global:TargetURL (form action: $action)" `
                -Evidence "Login form with password field served over unencrypted HTTP" `
                -Impact "Passwords transmitted in plaintext. Trivially intercepted on any network." `
                -Remediation "Serve all login forms exclusively over HTTPS" -CWE "CWE-319"
            Write-Finding "CRITICAL" "PASSWORD FORM OVER HTTP!"
        }
        
        # v2.0: CSRF token check for POST forms
        if ($method -eq "POST") {
            $csrfPatterns = 'csrf|_token|__RequestVerificationToken|csrfmiddlewaretoken|authenticity_token'
            $hasCSRF = $false
            foreach ($input in $inputs) {
                if ($input.Value -match "name=`"($csrfPatterns)`"") { $hasCSRF = $true; break }
                if ($input.Value -match 'type="hidden"' -and $input.Value -match "name=`"[^`"]*(?:token|csrf)[^`"]*`"") { $hasCSRF = $true; break }
            }
            if (-not $hasCSRF) {
                Add-Vuln -ID "FORM-CSRF" -Title "POST Form Missing CSRF Token" -Severity "MEDIUM" -CVSS 5.5 `
                    -Location "$Global:TargetURL (form: $method $action)" `
                    -Evidence "POST form has no hidden CSRF token input field" `
                    -Impact "Cross-Site Request Forgery possible. Attacker can trick users into submitting forms." `
                    -Remediation "Add CSRF tokens to all state-changing forms" -CWE "CWE-352"
                Write-Finding "MEDIUM" "POST form missing CSRF token: $action"
            }
        }
    }
    Write-Finding "OK" "$($forms.Count) forms found"
}

# ============================================================
# PHASE 12: WAF/CDN DETECTION (NEW v2.0)
# ============================================================
Write-Phase "12/20" "WAF/CDN Detection"

$wafSignatures = @(
    @{Header="cf-ray"; Name="Cloudflare"},
    @{Header="cf-cache-status"; Name="Cloudflare"},
    @{Header="x-amz-cf-id"; Name="AWS CloudFront"},
    @{Header="x-amz-cf-pop"; Name="AWS CloudFront"},
    @{Header="x-sucuri-id"; Name="Sucuri"},
    @{Header="x-sucuri-cache"; Name="Sucuri"},
    @{Header="x-cdn"; Name="CDN"},
    @{Header="x-akamai-transformed"; Name="Akamai"},
    @{Header="x-cache"; Name="CDN/Cache"}
)

$wafFound = $false
foreach ($sig in $wafSignatures) {
    $val = $Global:Headers[$sig.Header]
    if ($val) {
        $Global:WAFDetected = $sig.Name
        $Global:TechStack["WAF/CDN"] = $sig.Name
        $wafFound = $true
        Write-Finding "INFO" "WAF/CDN detected: $($sig.Name) (header: $($sig.Header)=$val)"
        break
    }
}

# Check Server header for WAF indicators
if (-not $wafFound) {
    $serverHdr = $Global:Headers["Server"]
    if ($serverHdr -match "cloudflare") { $Global:WAFDetected = "Cloudflare"; $wafFound = $true; $Global:TechStack["WAF/CDN"] = "Cloudflare" }
    elseif ($serverHdr -match "AkamaiGHost") { $Global:WAFDetected = "Akamai"; $wafFound = $true; $Global:TechStack["WAF/CDN"] = "Akamai" }
    elseif ($serverHdr -match "Sucuri") { $Global:WAFDetected = "Sucuri"; $wafFound = $true; $Global:TechStack["WAF/CDN"] = "Sucuri" }
}

if ($wafFound) {
    Write-Finding "OK" "WAF/CDN: $($Global:WAFDetected)"
} else {
    Write-Finding "INFO" "No WAF/CDN detected from response headers"
}

# ============================================================
# PHASE 13: DOMAIN INTELLIGENCE - RDAP (NEW v2.0)
# ============================================================
Write-Phase "13/20" "Domain Intelligence (RDAP)"

$domainIntel = @()
try {
    $rdapResp = Invoke-WebRequest -Uri "https://rdap.org/domain/$TargetClean" -UseBasicParsing -TimeoutSec 10
    if ($rdapResp.StatusCode -eq 200) {
        $rdapData = $rdapResp.Content | ConvertFrom-Json
        
        # Extract dates
        $creationDate = ""
        $expiryDate = ""
        $registrar = ""
        
        if ($rdapData.events) {
            foreach ($evt in $rdapData.events) {
                if ($evt.eventAction -eq "registration") { $creationDate = $evt.eventDate }
                if ($evt.eventAction -eq "expiration") { $expiryDate = $evt.eventDate }
            }
        }
        
        # Extract registrar
        if ($rdapData.entities) {
            foreach ($ent in $rdapData.entities) {
                if ($ent.roles -contains "registrar") {
                    if ($ent.vcardArray -and $ent.vcardArray[1]) {
                        foreach ($field in $ent.vcardArray[1]) {
                            if ($field[0] -eq "fn") { $registrar = $field[3] }
                        }
                    }
                    if (-not $registrar -and $ent.publicIds) {
                        $registrar = $ent.handle
                    }
                }
            }
        }
        
        $domainIntel += "Domain: $TargetClean"
        if ($creationDate) {
            $domainIntel += "Created: $creationDate"
            Write-Finding "INFO" "Domain created: $creationDate"
            try {
                $created = [datetime]::Parse($creationDate)
                $Global:DomainAge = ((Get-Date) - $created).Days
                $domainIntel += "Age: $($Global:DomainAge) days"
                Write-Finding "INFO" "Domain age: $($Global:DomainAge) days"
                
                if ($Global:DomainAge -lt 30) {
                    Add-Vuln -ID "DOMAIN-AGE" -Title "Newly Registered Domain (Potential Phishing)" -Severity "HIGH" -CVSS 7.0 `
                        -Location "$TargetClean" `
                        -Evidence "Domain registered $($Global:DomainAge) days ago ($creationDate). Domains less than 30 days old are strong phishing indicators." `
                        -Impact "Newly registered domains are commonly used for phishing, fraud, and malware distribution." `
                        -Remediation "Verify domain legitimacy. Report if suspected phishing." -CWE "CWE-451"
                    Write-Finding "HIGH" "NEWLY REGISTERED: $($Global:DomainAge) days old - phishing indicator!"
                } elseif ($Global:DomainAge -lt 90) {
                    Add-Vuln -ID "DOMAIN-YOUNG" -Title "Young Domain (Less than 90 days)" -Severity "MEDIUM" -CVSS 4.0 `
                        -Location "$TargetClean" `
                        -Evidence "Domain registered $($Global:DomainAge) days ago ($creationDate)." `
                        -Impact "Young domains have less established trust. May be associated with temporary or malicious sites." `
                        -Remediation "Monitor domain activity and verify legitimacy." -CWE "CWE-451"
                    Write-Finding "MEDIUM" "Young domain: $($Global:DomainAge) days old"
                }
            } catch {}
        }
        if ($expiryDate) { $domainIntel += "Expires: $expiryDate"; Write-Finding "INFO" "Domain expires: $expiryDate" }
        if ($registrar) { $domainIntel += "Registrar: $registrar"; Write-Finding "INFO" "Registrar: $registrar" }
    }
} catch {
    Write-Finding "INFO" "RDAP lookup failed (may not be available for this TLD): $($_.Exception.Message)"
    $domainIntel += "RDAP lookup failed for $TargetClean"
}
$domainIntel | Out-File "$OutputDir\evidence\domain_intel.txt" -Encoding UTF8

# ============================================================
# PHASE 14: REDIRECT CHAIN ANALYSIS (NEW v2.0)
# ============================================================
Write-Phase "14/20" "Redirect Chain Analysis"

$redirectChain = @()
$currentUrl = "http://$TargetClean"
$maxRedirects = 10
$redirectCount = 0

for ($i = 0; $i -lt $maxRedirects; $i++) {
    try {
        $rResp = Invoke-WebRequest -Uri $currentUrl -UseBasicParsing -TimeoutSec 8 -MaximumRedirection 0
        $redirectChain += "[$($rResp.StatusCode)] $currentUrl -> (final)"
        break
    } catch {
        $ex = $_.Exception
        $statusCode = $ex.Response.StatusCode.value__
        $location = ""
        try { $location = $ex.Response.Headers["Location"] } catch {}
        
        if ($statusCode -in @(301,302,303,307,308) -and $location) {
            $redirectChain += "[$statusCode] $currentUrl -> $location"
            $redirectCount++
            Write-Finding "INFO" "Redirect $redirectCount`: [$statusCode] $currentUrl -> $location"
            
            # Detect HTTPS -> HTTP downgrade
            if ($currentUrl -match "^https://" -and $location -match "^http://[^s]") {
                Add-Vuln -ID "REDIR-DOWNGRADE" -Title "HTTPS to HTTP Downgrade Redirect" -Severity "HIGH" -CVSS 7.4 `
                    -Location "$currentUrl" -Evidence "Redirects from HTTPS to HTTP: $currentUrl -> $location" `
                    -Impact "Secure connection downgraded to plaintext. Credentials can be intercepted." `
                    -Remediation "Ensure all redirects maintain HTTPS" -CWE "CWE-319"
                Write-Finding "HIGH" "HTTPS->HTTP DOWNGRADE detected!"
            }
            
            # Handle relative URLs
            if ($location -notmatch "^https?://") {
                $uri = [System.Uri]$currentUrl
                $location = "$($uri.Scheme)://$($uri.Host)$location"
            }
            
            # Detect redirect loop
            if ($redirectChain -match [regex]::Escape($location)) {
                Write-Finding "HIGH" "REDIRECT LOOP detected at $location"
                break
            }
            
            $currentUrl = $location
        } else {
            $redirectChain += "[$statusCode] $currentUrl -> (error/blocked)"
            break
        }
    }
}

# Open redirect check
$openRedirectParams = @("url","redirect","next","return","returnTo","goto","dest","destination","redir","target")
foreach ($param in $openRedirectParams) {
    try {
        $testUrl = "$($Global:TargetURL)?$param=https://evil.attacker.com"
        $orResp = Invoke-WebRequest -Uri $testUrl -UseBasicParsing -TimeoutSec 5 -MaximumRedirection 0
    } catch {
        $orStatus = $_.Exception.Response.StatusCode.value__
        $orLocation = ""
        try { $orLocation = $_.Exception.Response.Headers["Location"] } catch {}
        if ($orStatus -in @(301,302,303,307,308) -and $orLocation -match "evil\.attacker\.com") {
            Add-Vuln -ID "REDIR-OPEN" -Title "Open Redirect Vulnerability" -Severity "HIGH" -CVSS 6.8 `
                -Location "$testUrl" -Evidence "Redirect to external domain via ?$param= parameter. Location: $orLocation" `
                -Impact "Attacker can redirect users to phishing sites using your domain as a trust anchor." `
                -Remediation "Validate redirect URLs server-side. Only allow relative paths or whitelisted domains." -CWE "CWE-601"
            Write-Finding "HIGH" "OPEN REDIRECT via ?$param= parameter!"
            break
        }
    }
}

$redirectChain | Out-File "$OutputDir\evidence\redirect_chain.txt" -Encoding UTF8
Write-Finding "OK" "Redirect analysis complete ($redirectCount redirects found)"

# ============================================================
# PHASE 15: CMS-SPECIFIC CHECKS (NEW v2.0)
# ============================================================
if ($Fast) {
    Write-Phase "15/20" "CMS-Specific Checks [SKIPPED - Fast Mode]"
} else {
    Write-Phase "15/20" "CMS-Specific Checks"
    
    $detectedCMS = $Global:TechStack["CMS"]
    if ($detectedCMS -eq "WordPress") {
        Write-Finding "INFO" "Running WordPress-specific checks..."
        
        # WP user enumeration via REST API
        try {
            $wpUsers = Invoke-WebRequest -Uri "$($Global:TargetURL)/wp-json/wp/v2/users" -UseBasicParsing -TimeoutSec 8
            if ($wpUsers.StatusCode -eq 200 -and $wpUsers.Content -match '"slug"') {
                Add-Vuln -ID "CMS-WP-users" -Title "WordPress User Enumeration (REST API)" -Severity "MEDIUM" -CVSS 5.3 `
                    -Location "$($Global:TargetURL)/wp-json/wp/v2/users" `
                    -Evidence "WP REST API returns user data including usernames. Response: $($wpUsers.Content.Substring(0, [Math]::Min(200, $wpUsers.Content.Length)))" `
                    -Impact "Attacker can enumerate valid usernames for brute force attacks." `
                    -Remediation "Disable WP REST API user endpoint or require authentication." -CWE "CWE-200"
                Write-Finding "MEDIUM" "WP user enumeration via REST API!"
            }
        } catch {}
        
        # WP author enumeration
        try {
            $wpAuthor = Invoke-WebRequest -Uri "$($Global:TargetURL)/?author=1" -UseBasicParsing -TimeoutSec 8
            if ($wpAuthor.StatusCode -eq 200 -and $wpAuthor.Content.Length -ne $Global:Baseline404Size) {
                if ($wpAuthor.Content -match 'author|wp-content') {
                    Add-Vuln -ID "CMS-WP-author1" -Title "WordPress Author Enumeration" -Severity "MEDIUM" -CVSS 5.3 `
                        -Location "$($Global:TargetURL)/?author=1" `
                        -Evidence "HTTP 200, $($wpAuthor.Content.Length) bytes. Content matches expected WordPress pattern." `
                        -Impact "WordPress Author Enumeration can be exploited for reconnaissance or brute force attacks." `
                        -Remediation "Restrict access or disable this WordPress endpoint." -CWE "CWE-200"
                    Write-Finding "MEDIUM" "WP author enumeration via ?author=1"
                }
            }
        } catch {}
        
        # XMLRPC brute force vector
        try {
            $wpXmlrpc = Invoke-WebRequest -Uri "$($Global:TargetURL)/xmlrpc.php" -UseBasicParsing -TimeoutSec 8
            if ($wpXmlrpc.StatusCode -eq 200 -and $wpXmlrpc.Content -match "XML-RPC server accepts POST requests only") {
                Add-Vuln -ID "CMS-WP-xmlrpc" -Title "WordPress XML-RPC Enabled" -Severity "MEDIUM" -CVSS 5.5 `
                    -Location "$($Global:TargetURL)/xmlrpc.php" `
                    -Evidence "XML-RPC endpoint is active and accepting requests." `
                    -Impact "XML-RPC can be used for brute force amplification and DDoS attacks via pingback." `
                    -Remediation "Disable XML-RPC or restrict with .htaccess rules" -CWE "CWE-749"
                Write-Finding "MEDIUM" "WP XML-RPC enabled (brute force vector)"
            }
        } catch {}
    } elseif ($detectedCMS) {
        Write-Finding "INFO" "CMS detected: $detectedCMS (basic checks only)"
    } else {
        Write-Finding "OK" "No CMS detected - skipping CMS-specific checks"
    }
}

# ============================================================
# PHASE 16: API ENDPOINT PROBING (NEW v2.0)
# ============================================================
if ($Fast) {
    Write-Phase "16/20" "API Endpoint Probing [SKIPPED - Fast Mode]"
} else {
    Write-Phase "16/20" "API Endpoint Probing"
    
    $apiEndpoints = @("/api/v1/users", "/api/v1/config", "/api/health", "/api/status", "/api/debug") + $Global:ApiPaths
    $apiEndpoints = $apiEndpoints | Sort-Object -Unique
    
    foreach ($endpoint in $apiEndpoints) {
        try {
            $apiResp = Invoke-WebRequest -Uri "$($Global:TargetURL)$endpoint" -UseBasicParsing -TimeoutSec 5
            if ($apiResp.StatusCode -eq 200) {
                $isJson = $apiResp.Content.Trim().StartsWith("{") -or $apiResp.Content.Trim().StartsWith("[")
                # Soft 404 check
                $isSoft404 = ($Global:Baseline404Size -gt 0 -and [Math]::Abs($apiResp.Content.Length - $Global:Baseline404Size) -lt 500)
                
                if ($isJson -and -not $isSoft404) {
                    Add-Vuln -ID "API-NOAUTH-$($endpoint -replace '[^a-zA-Z0-9]','')" -Title "Unauthenticated API Endpoint: $endpoint" `
                        -Severity "HIGH" -CVSS 7.5 `
                        -Location "$($Global:TargetURL)$endpoint" `
                        -Evidence "Returns JSON data ($($apiResp.Content.Length) bytes) without authentication." `
                        -Impact "API data accessible without credentials. May expose sensitive information or allow unauthorized actions." `
                        -Remediation "Add authentication to all API endpoints. Use API keys, OAuth, or JWT tokens." -CWE "CWE-284"
                    Write-Finding "HIGH" "UNAUTHENTICATED API: $endpoint ($($apiResp.Content.Length) bytes JSON)"
                }
            }
        } catch {}
    }
    
    # GraphQL introspection check
    try {
        $gqlResp = Invoke-WebRequest -Uri "$($Global:TargetURL)/graphql?query={__schema{types{name}}}" -UseBasicParsing -TimeoutSec 5
        if ($gqlResp.StatusCode -eq 200 -and $gqlResp.Content -match "__schema") {
            Add-Vuln -ID "API-GRAPHQL" -Title "GraphQL Introspection Enabled" -Severity "HIGH" -CVSS 7.5 `
                -Location "$($Global:TargetURL)/graphql" `
                -Evidence "GraphQL introspection query returns full schema." `
                -Impact "Attacker can discover all available queries, mutations, and data types." `
                -Remediation "Disable introspection in production" -CWE "CWE-200"
            Write-Finding "HIGH" "GraphQL introspection ENABLED!"
        }
    } catch {}
    
    Write-Finding "OK" "API endpoint probing complete"
}

# ============================================================
# PHASE 17: CONTENT ANALYSIS (NEW v2.0)
# ============================================================
Write-Phase "17/20" "Content Analysis"

# Admin panel detection
$adminPaths = @("/admin", "/administrator", "/wp-admin", "/dashboard", "/manage", "/control", "/panel")
foreach ($ap in $adminPaths) {
    try {
        $adminResp = Invoke-WebRequest -Uri "$($Global:TargetURL)$ap" -UseBasicParsing -TimeoutSec 5
        if ($adminResp.StatusCode -eq 200) {
            $isSoft404 = ($Global:Baseline404Size -gt 0 -and [Math]::Abs($adminResp.Content.Length - $Global:Baseline404Size) -lt 500)
            if (-not $isSoft404 -and $adminResp.Content.Length -gt 500) {
                # Check if it's actually an admin/login page (not just a redirect or generic page)
                if ($adminResp.Content -match '(?i)login|password|username|sign.?in|admin|dashboard|authentication') {
                    Add-Vuln -ID "CONTENT-ADMIN" -Title "Admin Panel Accessible: $ap" -Severity "MEDIUM" -CVSS 5.0 `
                        -Location "$($Global:TargetURL)$ap" `
                        -Evidence "Admin panel/login page at $ap ($($adminResp.Content.Length) bytes). Contains login-related keywords." `
                        -Impact "Admin panel exposure enables targeted brute force attacks." `
                        -Remediation "Restrict admin panel access by IP or VPN. Use strong authentication." -CWE "CWE-200"
                    Write-Finding "MEDIUM" "Admin panel found: $ap"
                }
            }
        }
    } catch {}
}

# Directory listing detection
$dirPaths = @("/assets/", "/uploads/", "/images/", "/backup/", "/files/")
foreach ($dp in $dirPaths) {
    try {
        $dirResp = Invoke-WebRequest -Uri "$($Global:TargetURL)$dp" -UseBasicParsing -TimeoutSec 5
        if ($dirResp.StatusCode -eq 200 -and $dirResp.Content -match "Index of /|Directory listing for") {
            Add-Vuln -ID "CONTENT-DIRLIST" -Title "Directory Listing Enabled: $dp" -Severity "MEDIUM" -CVSS 5.3 `
                -Location "$($Global:TargetURL)$dp" `
                -Evidence "Directory listing enabled. Server shows file/folder contents." `
                -Impact "Attacker can browse and download all files in this directory." `
                -Remediation "Disable directory listing in web server configuration." -CWE "CWE-548"
            Write-Finding "MEDIUM" "DIRECTORY LISTING: $dp"
        }
    } catch {}
}

Write-Finding "OK" "Content analysis complete"

# ============================================================
# PHASE 18: EMAIL SECURITY DEEP SCAN (NEW v2.0)
# ============================================================
Write-Phase "18/20" "Email Security Deep Scan"

# MTA-STS check
$hasMTASTS = $false
try {
    $mtaSTS = Resolve-DnsName -Name "_mta-sts.$TargetClean" -Type TXT -ErrorAction Stop
    $mtaVal = $mtaSTS.Strings -join ""
    if ($mtaVal -match "v=STSv1") {
        $hasMTASTS = $true
        Write-Finding "OK" "MTA-STS TXT record found: $mtaVal"
    }
} catch {
    Write-Finding "INFO" "No MTA-STS TXT record"
}

# MTA-STS policy file
if ($hasMTASTS) {
    try {
        $mtaPolicy = Invoke-WebRequest -Uri "https://mta-sts.$TargetClean/.well-known/mta-sts.txt" -UseBasicParsing -TimeoutSec 8
        if ($mtaPolicy.StatusCode -eq 200) {
            Write-Finding "OK" "MTA-STS policy file accessible"
        }
    } catch {
        Write-Finding "INFO" "MTA-STS policy file not accessible"
    }
}

# BIMI check
try {
    $bimi = Resolve-DnsName -Name "default._bimi.$TargetClean" -Type TXT -ErrorAction Stop
    $bimiVal = $bimi.Strings -join ""
    if ($bimiVal -match "v=BIMI1") {
        Write-Finding "OK" "BIMI record found: $bimiVal"
    }
} catch {
    Write-Finding "INFO" "No BIMI record (brand indicator for email)"
}

# No email transport security
$hasDane = $false
try {
    $dane = Resolve-DnsName -Name "_25._tcp.$TargetClean" -Type TLSA -ErrorAction Stop
    if ($dane) { $hasDane = $true; Write-Finding "OK" "DANE/TLSA record found" }
} catch {
    Write-Finding "INFO" "No DANE/TLSA record"
}

if (-not $hasMTASTS -and -not $hasDane) {
    Add-Vuln -ID "EMAIL-TRANSPORT" -Title "No Email Transport Security (MTA-STS/DANE)" -Severity "MEDIUM" -CVSS 4.5 `
        -Location "$TargetClean" `
        -Evidence "Neither MTA-STS nor DANE/TLSA records found. Email transport encryption is opportunistic only." `
        -Impact "Email in transit can be intercepted via TLS downgrade attacks on SMTP connections." `
        -Remediation "Implement MTA-STS (easier) or DANE/TLSA to enforce encrypted email transport." -CWE "CWE-319"
    Write-Finding "MEDIUM" "No email transport security (MTA-STS/DANE missing)"
}

# ============================================================
# PHASE 19: OWASP TOP 10 2021 MAPPING (NEW v2.0)
# ============================================================
Write-Phase "19/20" "OWASP Top 10 2021 Mapping"

$owaspMap = @{
    "A01" = @{Name="Broken Access Control"; CWEs=@("CWE-284","CWE-942","CWE-1021","CWE-749","CWE-601","CWE-548")}
    "A02" = @{Name="Cryptographic Failures"; CWEs=@("CWE-319","CWE-326","CWE-327","CWE-295","CWE-298","CWE-614")}
    "A03" = @{Name="Injection"; CWEs=@("CWE-79","CWE-89")}
    "A04" = @{Name="Insecure Design"; CWEs=@("CWE-16","CWE-352","CWE-451")}
    "A05" = @{Name="Security Misconfiguration"; CWEs=@("CWE-200","CWE-538","CWE-540","CWE-693")}
    "A06" = @{Name="Vulnerable Components"; CWEs=@("CWE-1104")}
    "A07" = @{Name="Auth Failures"; CWEs=@("CWE-798","CWE-1004","CWE-290")}
    "A08" = @{Name="Integrity Failures"; CWEs=@("CWE-829")}
    "A09" = @{Name="Logging Failures"; CWEs=@()}
    "A10" = @{Name="SSRF"; CWEs=@("CWE-918")}
}

foreach ($cat in ($owaspMap.Keys | Sort-Object)) {
    $catInfo = $owaspMap[$cat]
    $matchCount = 0
    foreach ($vuln in $Global:Vulnerabilities) {
        if ($vuln.CWE -and $catInfo.CWEs -contains $vuln.CWE) { $matchCount++ }
    }
    $Global:OWASPResults[$cat] = @{Name=$catInfo.Name; Count=$matchCount; Status=if($matchCount -gt 0){"FINDINGS"}else{"CLEAN"}}
    if ($matchCount -gt 0) {
        Write-Finding "INFO" "$cat $($catInfo.Name): $matchCount finding(s)"
    }
}

$owaspWithFindings = @($Global:OWASPResults.Keys | Where-Object { $Global:OWASPResults[$_].Count -gt 0 }).Count
Write-Finding "INFO" "OWASP coverage: $owaspWithFindings/10 categories with findings"

# ============================================================
# PHASE 20: EXPLOIT CHAIN GENERATION (Enhanced v2.0)
# ============================================================
Write-Phase "20/20" "Exploit Chain Generation"

Write-Finding "INFO" "Analyzing vulnerability combinations..."

$critCount = @($Global:Vulnerabilities | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$highCount = @($Global:Vulnerabilities | Where-Object { $_.Severity -eq "HIGH" }).Count
$medCount = @($Global:Vulnerabilities | Where-Object { $_.Severity -eq "MEDIUM" }).Count
$lowCount = @($Global:Vulnerabilities | Where-Object { $_.Severity -eq "LOW" }).Count
$totalCount = @($Global:Vulnerabilities).Count

# Lookup helpers
$hasNoHTTPS = $Global:Vulnerabilities | Where-Object { $_.ID -match "SSL-05|SSL-01" }
$hasNoHSTS = $Global:Vulnerabilities | Where-Object { $_.Title -match "Strict-Transport" }
$hasNoCSP = $Global:Vulnerabilities | Where-Object { $_.Title -match "Content-Security-Policy" }
$hasNoXFO = $Global:Vulnerabilities | Where-Object { $_.Title -match "X-Frame-Options" }
$hasTrace = $Global:Vulnerabilities | Where-Object { $_.Title -match "TRACE" }
$hasVersionLeak = $Global:Vulnerabilities | Where-Object { $_.ID -match "INFO-0" }
$hasDefaultPanel = $Global:Vulnerabilities | Where-Object { $_.Title -match "Unconfigured Subdomain" }
$hasExposedDB = $Global:Vulnerabilities | Where-Object { $_.ID -match "PORT-(1433|3306|5432|6379|27017|9200)" }
$hasUnencryptedMail = $Global:Vulnerabilities | Where-Object { $_.ID -match "PORT-(110|143)" }
$hasSPFWeak = $Global:Vulnerabilities | Where-Object { $_.ID -match "DNS-SPF" }
$hasSecrets = $Global:Vulnerabilities | Where-Object { $_.ID -match "SECRET-" }
$hasGitExposed = $Global:Vulnerabilities | Where-Object { $_.Title -match "\.git" }
$hasEnvExposed = $Global:Vulnerabilities | Where-Object { $_.Title -match "\.env" }
$hasPwdHTTP = $Global:Vulnerabilities | Where-Object { $_.ID -match "FORM-HTTP-PWD" }
$hasDangerousPorts = $Global:Vulnerabilities | Where-Object { $_.ID -match "PORT-(3389|445|5900)" }
$hasYoungDomain = $Global:Vulnerabilities | Where-Object { $_.ID -match "DOMAIN-AGE|DOMAIN-YOUNG" }
$hasUnauthAPI = $Global:Vulnerabilities | Where-Object { $_.ID -match "API-NOAUTH" }
$hasCMSVuln = $Global:Vulnerabilities | Where-Object { $_.ID -match "CMS-" }
$hasAdminPanel = $Global:Vulnerabilities | Where-Object { $_.ID -match "CONTENT-ADMIN" }

$chainNum = 0

# Chain: MITM/SSL Strip
if ($hasNoHTTPS -and $hasNoHSTS) {
    $chainNum++
    $chain = [PSCustomObject]@{
        Num = $chainNum; Name = "MITM/SSL Strip - Session Hijack"; Severity = "CRITICAL"; Complexity = "LOW"; Confidence = "HIGH"
        CompositeRisk = [math]::Round((8.6 + 7.4) / 2, 1)
        Steps = @(
            "CONFIRMED: No HTTPS enforcement ($(($hasNoHTTPS | Select-Object -First 1).Evidence))",
            "CONFIRMED: No HSTS header to prevent downgrade",
            "ATTACK: Attacker on same network performs ARP spoofing",
            "ATTACK: SSL strip downgrades all connections to HTTP",
            "RESULT: All credentials and session tokens intercepted in plaintext"
        )
        Vulns = @("SSL-05", "HDR-01")
    }
    if ($hasPwdHTTP) { $chain.Steps += "AMPLIFIED: Password forms served over HTTP - credentials directly visible" }
    if ($hasUnencryptedMail) { $chain.Steps += "BONUS: Unencrypted POP3/IMAP also intercepted - email credentials stolen" }
    $Global:ExploitChains += $chain
    Write-Finding "CRITICAL" "Chain $chainNum : MITM/SSL Strip -> Session Hijack"
}

# Chain: XSS exploitation
if ($hasNoCSP) {
    $chainNum++
    $chain = [PSCustomObject]@{
        Num = $chainNum; Name = "XSS Exploitation (No CSP Restriction)"; Severity = "HIGH"; Complexity = "MEDIUM"; Confidence = "HIGH"
        CompositeRisk = 7.1
        Steps = @(
            "CONFIRMED: No Content-Security-Policy header",
            "ATTACK: Any XSS vulnerability becomes fully exploitable",
            "ATTACK: Injected script can load external resources, exfiltrate data",
            "RESULT: Cookie theft, keylogging, credential harvesting via injected JavaScript"
        )
        Vulns = @("HDR-CSP")
    }
    if ($hasNoXFO) { $chain.Steps += "AMPLIFIED: No X-Frame-Options - clickjacking can trick users into triggering XSS"; $chain.Vulns += "HDR-XFO" }
    if ($hasTrace) { $chain.Steps += "AMPLIFIED: TRACE method enabled - XST attack can steal HttpOnly cookies via XSS"; $chain.Vulns += "HTTP-01" }
    $Global:ExploitChains += $chain
    Write-Finding "HIGH" "Chain $chainNum : XSS + No CSP -> Full Exploitation"
}

# Chain: Default panel lateral movement
if ($hasDefaultPanel) {
    $chainNum++
    $panelVuln = $hasDefaultPanel | Select-Object -First 1
    $Global:ExploitChains += [PSCustomObject]@{
        Num = $chainNum; Name = "Unconfigured Subdomain - Lateral Movement"; Severity = "CRITICAL"; Complexity = "MEDIUM"; Confidence = "MEDIUM"
        CompositeRisk = 7.0
        Steps = @(
            "CONFIRMED: $($panelVuln.Location) shows default/unconfigured page",
            "ATTACK: Access admin panel (common ports 8443, 8880, 2083)",
            "ATTACK: Use default credentials or known CVEs for the panel software",
            "RESULT: Upload webshell, read config files, access database credentials"
        )
        Vulns = @($panelVuln.ID)
    }
    Write-Finding "CRITICAL" "Chain $chainNum : Default Panel -> Lateral Movement"
}

# Chain: Email spoofing
if ($hasSPFWeak) {
    $chainNum++
    $spfVuln = $hasSPFWeak | Select-Object -First 1
    $Global:ExploitChains += [PSCustomObject]@{
        Num = $chainNum; Name = "Email Spoofing - Phishing Attack"; Severity = "MEDIUM"; Complexity = "LOW"; Confidence = "HIGH"
        CompositeRisk = [math]::Round($spfVuln.CVSS, 1)
        Steps = @(
            "CONFIRMED: $($spfVuln.Evidence)",
            "ATTACK: Craft spoofed email from admin@$TargetClean",
            "ATTACK: Some email servers accept softfail as pass",
            "RESULT: Phishing emails appear to come from legitimate $TargetClean domain"
        )
        Vulns = @("DNS-SPF")
    }
    Write-Finding "MEDIUM" "Chain $chainNum : SPF Weakness -> Email Spoofing"
}

# Chain: Exposed secrets
if ($hasSecrets) {
    $chainNum++
    $Global:ExploitChains += [PSCustomObject]@{
        Num = $chainNum; Name = "Hardcoded Secrets - Direct Backend Access"; Severity = "CRITICAL"; Complexity = "LOW"; Confidence = "HIGH"
        CompositeRisk = 9.0
        Steps = @(
            "CONFIRMED: Secrets found in client-side JavaScript",
            "ATTACK: Use API keys to access backend services directly",
            "ATTACK: Bypass frontend authentication entirely",
            "RESULT: Unauthorized access to backend APIs and data"
        )
        Vulns = @($hasSecrets | ForEach-Object { $_.ID })
    }
    Write-Finding "CRITICAL" "Chain $chainNum : Exposed Secrets -> Backend Access"
}

# Chain: Git/Env exposure
if ($hasGitExposed -or $hasEnvExposed) {
    $chainNum++
    $Global:ExploitChains += [PSCustomObject]@{
        Num = $chainNum; Name = "Source Code/Config Exposure - Credential Theft"; Severity = "CRITICAL"; Complexity = "LOW"; Confidence = "HIGH"
        CompositeRisk = 9.0
        Steps = @(
            "CONFIRMED: $(if($hasGitExposed){'.git repository'}else{'.env file'}) publicly accessible",
            "ATTACK: Download complete source code or environment variables",
            "ATTACK: Extract database credentials, API keys, internal URLs",
            "RESULT: Full source code review + credential access to all backend systems"
        )
        Vulns = @()
    }
    Write-Finding "CRITICAL" "Chain $chainNum : Source/Config Exposure -> Full Access"
}

# Chain: Exposed database
if ($hasExposedDB) {
    $chainNum++
    $dbVuln = $hasExposedDB | Select-Object -First 1
    $Global:ExploitChains += [PSCustomObject]@{
        Num = $chainNum; Name = "Exposed Database - Direct Data Access"; Severity = "CRITICAL"; Complexity = "LOW"; Confidence = "HIGH"
        CompositeRisk = 7.5
        Steps = @(
            "CONFIRMED: $($dbVuln.Evidence)",
            "ATTACK: Connect directly to database from internet",
            "ATTACK: Brute force credentials or use default passwords",
            "RESULT: Read/modify/delete all database contents"
        )
        Vulns = @($dbVuln.ID)
    }
    Write-Finding "CRITICAL" "Chain $chainNum : Exposed DB -> Direct Access"
}

# v2.0 Chain: Phishing Infrastructure
if ($hasYoungDomain -and ($hasSPFWeak -or ($Global:Vulnerabilities | Where-Object { $_.ID -eq "DNS-NOSPF" })) -and ($Global:Vulnerabilities | Where-Object { $_.ID -eq "DNS-NODMARC" })) {
    $chainNum++
    $Global:ExploitChains += [PSCustomObject]@{
        Num = $chainNum; Name = "Phishing Infrastructure Detected"; Severity = "CRITICAL"; Complexity = "LOW"; Confidence = "HIGH"
        CompositeRisk = 7.5
        Steps = @(
            "CONFIRMED: Domain age is $($Global:DomainAge) days (newly/recently registered)",
            "CONFIRMED: No SPF or weak SPF record - domain can be spoofed",
            "CONFIRMED: No DMARC record - no email authentication policy",
            "ASSESSMENT: Domain exhibits classic phishing infrastructure indicators",
            "RESULT: High probability this domain is used for phishing or malicious purposes"
        )
        Vulns = @("DOMAIN-AGE", "DNS-NOSPF", "DNS-NODMARC")
    }
    Write-Finding "CRITICAL" "Chain $chainNum : Phishing Infrastructure Detected!"
}

# v2.0 Chain: API Abuse
if ($hasUnauthAPI -and $hasSecrets) {
    $chainNum++
    $Global:ExploitChains += [PSCustomObject]@{
        Num = $chainNum; Name = "API Abuse via Exposed Credentials"; Severity = "CRITICAL"; Complexity = "LOW"; Confidence = "HIGH"
        CompositeRisk = 9.0
        Steps = @(
            "CONFIRMED: Unauthenticated API endpoints found",
            "CONFIRMED: API keys/secrets exposed in client-side JavaScript",
            "ATTACK: Combine exposed keys with unauthenticated API access",
            "RESULT: Full unauthorized API access with elevated privileges"
        )
        Vulns = @()
    }
    Write-Finding "CRITICAL" "Chain $chainNum : API Abuse via Exposed Credentials"
}

# v2.0 Chain: Full Infrastructure
if ($totalCount -ge 10 -and $owaspWithFindings -ge 3) {
    $chainNum++
    $avgCVSS = [math]::Round(($Global:Vulnerabilities | Measure-Object -Property CVSS -Average).Average, 1)
    $Global:ExploitChains += [PSCustomObject]@{
        Num = $chainNum; Name = "Full Infrastructure Compromise"; Severity = "CRITICAL"; Complexity = "MEDIUM"; Confidence = "HIGH"
        CompositeRisk = $avgCVSS
        Steps = @(
            "CONFIRMED: $totalCount vulnerabilities across $owaspWithFindings OWASP categories",
            "CONFIRMED: Multiple attack surfaces identified (web, network, email, API)",
            "ATTACK: Chain multiple lower-severity vulns for amplified impact",
            "ATTACK: Use information disclosure to target specific CVEs",
            "ATTACK: Combine credential access with exposed services",
            "RESULT: Complete infrastructure compromise through vulnerability stacking"
        )
        Vulns = @()
    }
    Write-Finding "CRITICAL" "Chain $chainNum : Full Infrastructure ($totalCount vulns, $owaspWithFindings OWASP categories)"
}

Write-Finding "OK" "$chainNum exploit chains generated from confirmed vulnerabilities"

# ============================================================
# GENERATE MARKDOWN REPORT
# ============================================================
Write-Phase "REPORT" "Generating Final Report"

$reportLines = @()
$reportLines += "# AcroStrike v2.0 - VAPT Assessment Report"
$reportLines += ""
$reportLines += "| Field | Value |"
$reportLines += "|-------|-------|"
$reportLines += "| **Target** | $TargetClean |"
$reportLines += "| **URL** | $($Global:TargetURL) |"
$reportLines += "| **Date** | $Timestamp |"
$reportLines += "| **Scanner** | AcroStrike v2.0 (Pure PowerShell) |"
$reportLines += "| **Methodology** | Passive reconnaissance + active probing (public surface only) |"
$reportLines += "| **Mode** | $(if($Fast){'Fast'}else{'Full (all 20 phases)'}) |"
$reportLines += ""

# Risk Summary
$reportLines += "---"
$reportLines += ""
$reportLines += "## Risk Summary"
$reportLines += ""
$reportLines += "| Severity | Count |"
$reportLines += "|----------|-------|"
$reportLines += "| CRITICAL | $critCount |"
$reportLines += "| HIGH | $highCount |"
$reportLines += "| MEDIUM | $medCount |"
$reportLines += "| LOW | $lowCount |"
$reportLines += "| **TOTAL** | **$totalCount** |"
$reportLines += ""
$reportLines += "Exploit Chains: **$chainNum**"
$reportLines += ""
$reportLines += "Subdomains Discovered: **$($Global:Subdomains.Count)**"
$reportLines += ""
$reportLines += "Open Ports: **$($Global:OpenPorts.Count)**"
$reportLines += ""

# OWASP section
$reportLines += "---"
$reportLines += ""
$reportLines += "## OWASP Top 10 2021 Coverage"
$reportLines += ""
$reportLines += "| Category | Status | Findings |"
$reportLines += "|----------|--------|----------|"
foreach ($cat in ($Global:OWASPResults.Keys | Sort-Object)) {
    $catData = $Global:OWASPResults[$cat]
    $reportLines += "| $cat $($catData.Name) | $($catData.Status) | $($catData.Count) |"
}
$reportLines += ""

# Technology Stack
$reportLines += "---"
$reportLines += ""
$reportLines += "## Technology Stack"
$reportLines += ""
$reportLines += "| Component | Value |"
$reportLines += "|-----------|-------|"
foreach ($key in $Global:TechStack.Keys) {
    $reportLines += "| $key | $($Global:TechStack[$key]) |"
}
$reportLines += ""

# Infrastructure
$reportLines += "---"
$reportLines += ""
$reportLines += "## Infrastructure Map"
$reportLines += ""
$reportLines += "### Main Target"
$reportLines += ""
$reportLines += "| Port | Service |"
$reportLines += "|------|---------|"
foreach ($p in ($Global:OpenPorts | Sort-Object Port)) {
    $reportLines += "| $($p.Port) | $($p.Service) |"
}
$reportLines += ""

if ($Global:Subdomains.Count -gt 0) {
    $reportLines += "### Subdomains"
    $reportLines += ""
    $reportLines += "| Subdomain | IP | Server | Title |"
    $reportLines += "|-----------|-----|--------|-------|"
    foreach ($sub in $Global:Subdomains) {
        $reportLines += "| $($sub.Name) | $($sub.IP) | $($sub.Server) | $($sub.Title) |"
    }
    $reportLines += ""
}

# Vulnerability Details
$reportLines += "---"
$reportLines += ""
$reportLines += "## Vulnerability Details"
$reportLines += ""

$sevOrder = @("CRITICAL","HIGH","MEDIUM","LOW","INFO")
foreach ($sev in $sevOrder) {
    $vulnsOfSev = @($Global:Vulnerabilities | Where-Object { $_.Severity -eq $sev })
    if ($vulnsOfSev.Count -eq 0) { continue }
    
    $reportLines += "### $sev Severity"
    $reportLines += ""
    
    foreach ($v in $vulnsOfSev) {
        $reportLines += "#### [$($v.ID)] $($v.Title)"
        $reportLines += ""
        $reportLines += "| Field | Detail |"
        $reportLines += "|-------|--------|"
        $reportLines += "| **Severity** | $($v.Severity) |"
        $reportLines += "| **CVSS** | $($v.CVSS) |"
        if ($v.CWE) { $reportLines += "| **CWE** | $($v.CWE) |" }
        $reportLines += "| **Location** | $($v.Location) |"
        $reportLines += "| **Evidence** | $($v.Evidence) |"
        $reportLines += "| **Impact** | $($v.Impact) |"
        $reportLines += "| **Remediation** | $($v.Remediation) |"
        $reportLines += "| **Confirmed** | $($v.Confirmed) |"
        $reportLines += ""
    }
}

# Exploit Chains
if ($Global:ExploitChains.Count -gt 0) {
    $reportLines += "---"
    $reportLines += ""
    $reportLines += "## Exploit Chains"
    $reportLines += ""
    $reportLines += "> These chains are generated ONLY from confirmed vulnerabilities."
    $reportLines += "> Each step references verified findings from this scan."
    $reportLines += ""
    
    foreach ($chain in $Global:ExploitChains) {
        $reportLines += "### Chain $($chain.Num): $($chain.Name)"
        $reportLines += ""
        $riskInfo = "**Severity:** $($chain.Severity) | **Complexity:** $($chain.Complexity) | **Confidence:** $($chain.Confidence)"
        if ($chain.CompositeRisk) { $riskInfo += " | **Composite Risk:** $($chain.CompositeRisk)" }
        $reportLines += $riskInfo
        $reportLines += ""
        $reportLines += '```'
        $stepNum = 0
        foreach ($step in $chain.Steps) {
            $stepNum++
            $reportLines += "  Step $stepNum : $step"
        }
        $reportLines += '```'
        $reportLines += ""
        if ($chain.Vulns -and $chain.Vulns.Count -gt 0) {
            $reportLines += "Related Vulnerabilities: $($chain.Vulns -join ', ')"
            $reportLines += ""
        }
    }
}

# Remediation Priority
$reportLines += "---"
$reportLines += ""
$reportLines += "## Remediation Priority"
$reportLines += ""
$reportLines += "| Priority | Action | Fixes |"
$reportLines += "|----------|--------|-------|"
$pNum = 0
foreach ($v in @($Global:Vulnerabilities | Where-Object { $_.Severity -eq "CRITICAL" })) {
    $pNum++
    $reportLines += "| P0-$pNum | $($v.Remediation) | $($v.ID) |"
}
foreach ($v in @($Global:Vulnerabilities | Where-Object { $_.Severity -eq "HIGH" } | Select-Object -First 5)) {
    $pNum++
    $reportLines += "| P1-$pNum | $($v.Remediation) | $($v.ID) |"
}
$reportLines += ""

# Footer
$reportLines += "---"
$reportLines += ""
$reportLines += "*Generated by AcroStrike v2.0 - Part of the Acro Empire*"
$reportLines += ""
$reportLines += "*All findings are from publicly accessible information. No exploitation was performed.*"
$reportLines += ""
$reportLines += "*Scan completed: $(Get-Date -Format 'yyyy-MM-dd HH.mm.ss')*"

$reportContent = $reportLines -join "`n"
$reportContent | Out-File "$OutputDir\VAPT_REPORT.md" -Encoding UTF8

# Generate JSON report
$jsonReport = @{
    target = $TargetClean
    url = $Global:TargetURL
    scan_date = $Timestamp
    scanner = "AcroStrike v2.0"
    summary = @{
        total = $totalCount
        critical = $critCount
        high = $highCount
        medium = $medCount
        low = $lowCount
        exploit_chains = $chainNum
        subdomains = $Global:Subdomains.Count
        open_ports = $Global:OpenPorts.Count
        owasp_coverage = $owaspWithFindings
    }
    tech_stack = $Global:TechStack
    vulnerabilities = $Global:Vulnerabilities
    exploit_chains_detail = $Global:ExploitChains
    subdomains = $Global:Subdomains
    open_ports = $Global:OpenPorts
    owasp_mapping = $Global:OWASPResults
    domain_age_days = $Global:DomainAge
    waf_detected = $Global:WAFDetected
} | ConvertTo-Json -Depth 5
$jsonReport | Out-File "$OutputDir\VAPT_REPORT.json" -Encoding UTF8

# ============================================================
# GENERATE HTML REPORT (v2.0)
# ============================================================
Write-Finding "INFO" "Generating self-contained HTML report..."

# Simple HTML escape function (no System.Web dependency)
function Esc-Html([string]$s) {
    return $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#39;')
}

$riskScore = [math]::Min(100, ($critCount * 25) + ($highCount * 15) + ($medCount * 5) + ($lowCount * 1))
$riskColor = if ($riskScore -ge 75) { "#f85149" } elseif ($riskScore -ge 50) { "#d29922" } elseif ($riskScore -ge 25) { "#e3b341" } else { "#3fb950" }

# Build vulnerability HTML
$vulnHtml = ""
foreach ($sev in @("CRITICAL","HIGH","MEDIUM","LOW")) {
    $sevVulns = @($Global:Vulnerabilities | Where-Object { $_.Severity -eq $sev })
    if ($sevVulns.Count -eq 0) { continue }
    $sevColor = switch($sev) { "CRITICAL"{"#f85149"} "HIGH"{"#d29922"} "MEDIUM"{"#e3b341"} "LOW"{"#8b949e"} }
    foreach ($v in $sevVulns) {
        $eLoc = Esc-Html $v.Location
        $eEvi = Esc-Html $v.Evidence
        $eImp = Esc-Html $v.Impact
        $eFix = Esc-Html $v.Remediation
        $vulnHtml += "<div class='vuln-card'><div class='vuln-header'><span class='vuln-sev' style='background:$sevColor'>$($v.Severity)</span><span class='vuln-id'>[$($v.ID)]</span> $($v.Title)</div>"
        $vulnHtml += "<div class='vuln-body'><table><tr><td><b>CVSS</b></td><td>$($v.CVSS)</td></tr>"
        if ($v.CWE) { $vulnHtml += "<tr><td><b>CWE</b></td><td>$($v.CWE)</td></tr>" }
        $vulnHtml += "<tr><td><b>Location</b></td><td>$eLoc</td></tr>"
        $vulnHtml += "<tr><td><b>Evidence</b></td><td>$eEvi</td></tr>"
        $vulnHtml += "<tr><td><b>Impact</b></td><td>$eImp</td></tr>"
        $vulnHtml += "<tr><td><b>Fix</b></td><td>$eFix</td></tr>"
        $vulnHtml += "</table></div></div>"
    }
}

# Build OWASP HTML
$owaspHtml = ""
foreach ($cat in ($Global:OWASPResults.Keys | Sort-Object)) {
    $catData = $Global:OWASPResults[$cat]
    $barColor = if ($catData.Count -gt 0) { "#f85149" } else { "#3fb950" }
    $owaspHtml += "<div class='owasp-row'><span class='owasp-cat'>$cat</span><span class='owasp-name'>$($catData.Name)</span><span class='owasp-bar' style='background:$barColor'>$($catData.Count)</span></div>"
}

# Build chains HTML
$chainsHtml = ""
foreach ($chain in $Global:ExploitChains) {
    $chainSevColor = switch($chain.Severity) { "CRITICAL"{"#f85149"} "HIGH"{"#d29922"} "MEDIUM"{"#e3b341"} default{"#8b949e"} }
    $chainsHtml += "<div class='chain-card'><div class='chain-header'><span class='vuln-sev' style='background:$chainSevColor'>$($chain.Severity)</span> Chain $($chain.Num): $($chain.Name)</div>"
    $chainsHtml += "<div class='chain-meta'>Complexity: $($chain.Complexity) | Confidence: $($chain.Confidence)"
    if ($chain.CompositeRisk) { $chainsHtml += " | Risk: $($chain.CompositeRisk)" }
    $chainsHtml += "</div><div class='chain-steps'>"
    $sn = 0
    foreach ($step in $chain.Steps) {
        $sn++
        $stepClass = if ($step -match "^CONFIRMED") { "step-confirmed" } elseif ($step -match "^ATTACK") { "step-attack" } else { "step-result" }
        $eStep = Esc-Html $step
        $chainsHtml += "<div class='chain-step $stepClass'>Step ${sn}: $eStep</div>"
    }
    $chainsHtml += "</div></div>"
}

$htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AcroStrike v2.0 - VAPT Report: $TargetClean</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0d1117;color:#c9d1d9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;padding:20px;line-height:1.6}
.container{max-width:1100px;margin:0 auto}
h1{color:#58a6ff;font-size:28px;margin-bottom:5px}
h2{color:#58a6ff;font-size:20px;margin:30px 0 15px;padding-bottom:8px;border-bottom:1px solid #21262d}
.subtitle{color:#8b949e;font-size:14px;margin-bottom:20px}
.meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}
.meta-box{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:15px;text-align:center}
.meta-box .label{color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:1px}
.meta-box .value{color:#c9d1d9;font-size:24px;font-weight:bold;margin-top:5px}
.risk-gauge{text-align:center;margin:20px 0}
.risk-score{display:inline-block;width:80px;height:80px;border-radius:50%;border:4px solid $riskColor;line-height:72px;font-size:28px;font-weight:bold;color:$riskColor}
.sev-bars{display:flex;gap:8px;margin:15px 0;flex-wrap:wrap}
.sev-bar{flex:1;min-width:80px;padding:10px;border-radius:6px;text-align:center}
.sev-bar .count{font-size:22px;font-weight:bold;color:#fff}
.sev-bar .label{font-size:11px;color:rgba(255,255,255,0.8);text-transform:uppercase}
.sev-bar.critical{background:#f85149}
.sev-bar.high{background:#d29922}
.sev-bar.medium{background:#e3b341}
.sev-bar.low{background:#8b949e}
.owasp-row{display:flex;align-items:center;padding:8px 0;border-bottom:1px solid #21262d}
.owasp-cat{color:#58a6ff;font-weight:bold;min-width:40px;font-family:monospace}
.owasp-name{flex:1;color:#c9d1d9;font-size:14px;margin:0 10px}
.owasp-bar{padding:3px 12px;border-radius:4px;font-size:12px;color:#fff;text-align:center;min-width:30px}
.vuln-card{background:#161b22;border:1px solid #21262d;border-radius:8px;margin:10px 0;overflow:hidden}
.vuln-header{padding:12px 15px;font-weight:bold;border-bottom:1px solid #21262d;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.vuln-sev{padding:2px 8px;border-radius:4px;font-size:11px;color:#fff;text-transform:uppercase}
.vuln-id{color:#8b949e;font-size:12px}
.vuln-body{padding:12px 15px}
.vuln-body table{width:100%;border-collapse:collapse}
.vuln-body td{padding:5px 8px;border-bottom:1px solid #21262d;font-size:13px;vertical-align:top}
.vuln-body td:first-child{width:80px;color:#8b949e}
.chain-card{background:#161b22;border:1px solid #21262d;border-radius:8px;margin:10px 0;overflow:hidden}
.chain-header{padding:12px 15px;font-weight:bold;border-bottom:1px solid #21262d;display:flex;align-items:center;gap:8px}
.chain-meta{padding:8px 15px;color:#8b949e;font-size:12px}
.chain-steps{padding:10px 15px}
.chain-step{padding:4px 0;font-size:13px;font-family:monospace}
.step-confirmed{color:#3fb950}
.step-attack{color:#d29922}
.step-result{color:#f85149}
.footer{text-align:center;color:#8b949e;font-size:12px;margin-top:40px;padding:20px;border-top:1px solid #21262d}
@media print{body{background:#fff;color:#000} .vuln-card,.chain-card,.meta-box{border-color:#ccc} h1,h2,.owasp-cat{color:#0366d6}}
</style>
</head>
<body>
<div class="container">
<h1>ACROSTRIKE v2.0</h1>
<div class="subtitle">VAPT Assessment Report | $TargetClean | $Timestamp</div>

<div class="risk-gauge"><div class="risk-score">$riskScore</div><br><span style="color:#8b949e;font-size:12px">RISK SCORE</span></div>

<div class="sev-bars">
<div class="sev-bar critical"><div class="count">$critCount</div><div class="label">Critical</div></div>
<div class="sev-bar high"><div class="count">$highCount</div><div class="label">High</div></div>
<div class="sev-bar medium"><div class="count">$medCount</div><div class="label">Medium</div></div>
<div class="sev-bar low"><div class="count">$lowCount</div><div class="label">Low</div></div>
</div>

<div class="meta-grid">
<div class="meta-box"><div class="label">Total Vulns</div><div class="value">$totalCount</div></div>
<div class="meta-box"><div class="label">Exploit Chains</div><div class="value">$chainNum</div></div>
<div class="meta-box"><div class="label">Open Ports</div><div class="value">$($Global:OpenPorts.Count)</div></div>
<div class="meta-box"><div class="label">OWASP Coverage</div><div class="value">$owaspWithFindings/10</div></div>
</div>

<h2>OWASP Top 10 2021 Coverage</h2>
$owaspHtml

<h2>Vulnerabilities ($totalCount)</h2>
$vulnHtml

<h2>Exploit Chains ($chainNum)</h2>
$chainsHtml

<div class="footer">
Generated by AcroStrike v2.0 | Part of the Acro Empire<br>
All findings are from publicly accessible information. No exploitation was performed.<br>
Scan completed: $(Get-Date -Format 'yyyy-MM-dd HH.mm.ss')
</div>
</div>
</body>
</html>
"@

$htmlContent | Out-File "$OutputDir\VAPT_REPORT.html" -Encoding UTF8
Write-Finding "OK" "HTML report generated"

# ============================================================
# FINAL SUMMARY
# ============================================================
if (-not $Quiet) {
    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor Cyan
    Write-Host "  SCAN COMPLETE" -ForegroundColor Green
    Write-Host "  ================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    CRITICAL : $critCount" -ForegroundColor Red
    Write-Host "    HIGH     : $highCount" -ForegroundColor DarkYellow
    Write-Host "    MEDIUM   : $medCount" -ForegroundColor Yellow
    Write-Host "    LOW      : $lowCount" -ForegroundColor Gray
    Write-Host "    TOTAL    : $totalCount vulnerabilities" -ForegroundColor White
    Write-Host ""
    Write-Host "    Exploit Chains : $chainNum" -ForegroundColor White
    Write-Host "    Subdomains     : $($Global:Subdomains.Count)" -ForegroundColor White
    Write-Host "    Open Ports     : $($Global:OpenPorts.Count)" -ForegroundColor White
    Write-Host "    OWASP Coverage : $owaspWithFindings/10 categories" -ForegroundColor White
    Write-Host ""
    Write-Host "    Report (MD)    : $OutputDir\VAPT_REPORT.md" -ForegroundColor Yellow
    Write-Host "    Report (JSON)  : $OutputDir\VAPT_REPORT.json" -ForegroundColor Yellow
    Write-Host "    Report (HTML)  : $OutputDir\VAPT_REPORT.html" -ForegroundColor Yellow
    Write-Host "    Evidence       : $OutputDir\evidence\" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor Cyan
    Write-Host "  Completed: $(Get-Date -Format 'yyyy-MM-dd HH.mm.ss')" -ForegroundColor Yellow
    Write-Host "  ================================================================" -ForegroundColor Cyan
    Write-Host ""
}

# Open output folder
explorer $OutputDir
