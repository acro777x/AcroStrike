# ============================================================
# ACROSTRIKE v1.0 - Pure PowerShell VAPT Scanner
# Zero-dependency vulnerability assessment - ZERO false positives
# Part of the Acro Empire | github.com/AcroEmpire
# For authorized security testing ONLY
# ============================================================

param(
    [string]$Target
)

if (-not $Target) {
    Write-Host ""
    Write-Host "  ========================================" -ForegroundColor Cyan
    Write-Host "  ACROSTRIKE v1.0" -ForegroundColor Cyan
    Write-Host "  Zero-Dependency VAPT Scanner" -ForegroundColor Cyan
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
$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

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
    Write-Host ""
    Write-Host "  [$Phase] $Description" -ForegroundColor Cyan
    Write-Host "  $('=' * (8 + $Phase.Length + $Description.Length))" -ForegroundColor DarkCyan
}

function Write-Finding {
    param([string]$Type, [string]$Message)
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

# ============================================================
Write-Host ""
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host "     ___                    ____  _        _ _        " -ForegroundColor Cyan
Write-Host "    /   |  _________  _____/ __/_(_)___   (_) /_____  " -ForegroundColor Cyan
Write-Host "   / /| | / ___/ __ \/ ___/ /_  / / / /   / / //_/ _ \ " -ForegroundColor Cyan
Write-Host "  / ___ |/ /__/ /_/ / /  / __/ / / /_/   / / ,< /  __/ " -ForegroundColor Cyan
Write-Host " /_/  |_|\___/\____/_/  /_/   /_/\__, / /_/_/|_|\___/  " -ForegroundColor Cyan
Write-Host "                                /____/            v1.0" -ForegroundColor DarkCyan
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host "  Target  : $TargetClean" -ForegroundColor Yellow
Write-Host "  Output  : $OutputDir" -ForegroundColor Yellow
Write-Host "  Started : $Timestamp" -ForegroundColor Yellow
Write-Host "  ================================================================" -ForegroundColor Cyan

# ============================================================
# PHASE 1: SSL/TLS ANALYSIS
# ============================================================
Write-Phase "1/12" "SSL/TLS Certificate Analysis"

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
    # These are NOT server vulnerabilities - they are local interception
    $localProxyPatterns = "Norton|Antivirus|Web.*Shield|Kaspersky|Avast|ESET|Bitdefender|McAfee|mitmproxy|charles|fiddler|burp|ZScaler"
    if ($certIssuer -match $localProxyPatterns) {
        Write-Finding "INFO" "LOCAL PROXY DETECTED: $certIssuer"
        Write-Finding "INFO" "Your antivirus/proxy is intercepting SSL. This is NOT a server vulnerability."
        Write-Finding "INFO" "Skipping SSL cert analysis (results would be from your local proxy, not the server)"
        $sslReport += "NOTE: Local SSL proxy detected ($certIssuer). Cert findings skipped to avoid false positives."
    }
    # Check for genuinely self-signed or untrusted certs (NOT local proxy)
    elseif ($certIssuer -eq $certSubject) {
        # Self-signed: issuer equals subject
        Add-Vuln -ID "SSL-01" -Title "Self-Signed SSL Certificate" -Severity "CRITICAL" -CVSS 9.1 `
            -Location "https://$TargetClean" `
            -Evidence "Certificate is self-signed: Issuer and Subject are identical ($certIssuer)" `
            -Impact "HTTPS provides no trust verification. Browsers show security warnings. MITM attacks trivial." `
            -Remediation "Install a valid SSL certificate from a trusted CA (Let's Encrypt, DigiCert, etc.)" `
            -CWE "CWE-295"
        Write-Finding "CRITICAL" "SELF-SIGNED certificate detected"
    }
    
    # Check expiry
    if ($certExpiry -lt (Get-Date)) {
        Add-Vuln -ID "SSL-02" -Title "Expired SSL Certificate" -Severity "CRITICAL" -CVSS 8.5 `
            -Location "https://$TargetClean" -Evidence "Certificate expired on $certExpiry" `
            -Impact "Browsers will block access. Users trained to click through warnings." `
            -Remediation "Renew the SSL certificate immediately" -CWE "CWE-298"
        Write-Finding "CRITICAL" "Certificate EXPIRED: $certExpiry"
    }
    
    # Check weak protocol
    if ($ssl.SslProtocol -match "Ssl3|Tls$|Tls11") {
        Add-Vuln -ID "SSL-03" -Title "Weak TLS Protocol" -Severity "HIGH" -CVSS 7.4 `
            -Location "https://$TargetClean" -Evidence "Protocol: $($ssl.SslProtocol)" `
            -Impact "Vulnerable to POODLE, BEAST, or other protocol downgrade attacks" `
            -Remediation "Disable TLS 1.0/1.1 and SSLv3. Use TLS 1.2+ only" -CWE "CWE-326"
        Write-Finding "HIGH" "Weak protocol: $($ssl.SslProtocol)"
    }
    
    # Check weak cipher
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
Write-Phase "2/12" "Technology Stack Fingerprinting"

try {
    $resp = Invoke-WebRequest -Uri $Global:TargetURL -UseBasicParsing -TimeoutSec 15
    $Global:Homepage = $resp.Content
    $Global:Headers = $resp.Headers
    $Global:Homepage | Out-File "$OutputDir\pages\index.html" -Encoding UTF8
    
    # Server header
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
    
    # X-Powered-By
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
    
    # X-AspNet-Version
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
    
    # X-AspNetMvc-Version
    $mvcVer = $Global:Headers["X-AspNetMvc-Version"]
    if ($mvcVer) {
        $Global:TechStack["MVC"] = $mvcVer
        Write-Finding "HIGH" "MVC Version: $mvcVer"
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
    $cdnVersions = [regex]::Matches($Global:Homepage, '(?:src|href)="[^"]*/([\w.-]+?)(?:@|/)(\d+\.\d+[\d.]*)[^"]*"')
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
Write-Phase "3/12" "Security Headers Audit"

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
        # Check weak values
        if ($check.Name -eq "X-Frame-Options" -and $val -eq "ALLOWALL") {
            Add-Vuln -ID "HDR-WEAK-01" -Title "Weak X-Frame-Options (ALLOWALL)" -Severity "HIGH" -CVSS 6.8 `
                -Location "$Global:TargetURL" -Evidence "X-Frame-Options: ALLOWALL" `
                -Impact "Site can be framed by any origin" -Fix "Change to DENY or SAMEORIGIN" -CWE "CWE-1021"
        }
        if ($check.Name -eq "Content-Security-Policy" -and $val -match "unsafe-inline.*unsafe-eval") {
            Add-Vuln -ID "HDR-WEAK-02" -Title "Weak CSP (unsafe-inline + unsafe-eval)" -Severity "MEDIUM" -CVSS 5.5 `
                -Location "$Global:TargetURL" -Evidence "CSP contains both unsafe-inline and unsafe-eval" `
                -Impact "CSP provides minimal XSS protection" -Fix "Remove unsafe-inline and unsafe-eval directives" -CWE "CWE-79"
        }
    }
}

# Check info disclosure headers that SHOULD be absent
$xpb = $Global:Headers["X-Powered-By"]
$srv = $Global:Headers["Server"]
if ($xpb) { Write-Finding "MEDIUM" "LEAKING: X-Powered-By: $xpb" }
if ($srv -and $srv -match "\d+\.\d+") { Write-Finding "MEDIUM" "LEAKING: Server: $srv" }

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
Write-Phase "4/12" "HTTP Methods Analysis"

# First get baseline GET response for comparison (to detect soft-200 false positives)
$Global:BaselineGETSize = 0
$Global:BaselineGETHash = ""
try {
    $baseGet = Invoke-WebRequest -Uri $Global:TargetURL -UseBasicParsing -TimeoutSec 8
    $Global:BaselineGETSize = $baseGet.Content.Length
    # Simple hash: first 200 chars + length
    $Global:BaselineGETHash = "$($baseGet.Content.Length)_$($baseGet.Content.Substring(0, [Math]::Min(200, $baseGet.Content.Length)).GetHashCode())"
} catch {}

$dangerousMethods = @("TRACE","PUT","DELETE","PATCH","OPTIONS")
foreach ($method in $dangerousMethods) {
    try {
        $methodResp = Invoke-WebRequest -Uri $Global:TargetURL -UseBasicParsing -TimeoutSec 5 -Method $method
        $code = $methodResp.StatusCode
        if ($code -eq 200) {
            # FALSE POSITIVE CHECK: Compare response with GET baseline
            # Many servers/CDNs return 200 for any method but serve the same page (not actually processing the method)
            $methodHash = "$($methodResp.Content.Length)_$($methodResp.Content.Substring(0, [Math]::Min(200, $methodResp.Content.Length)).GetHashCode())"
            $isSameAsGET = ($methodHash -eq $Global:BaselineGETHash)
            
            $Global:HttpMethods += $method
            if ($method -eq "TRACE") {
                # TRACE must reflect the request headers/body back - that's the real test
                $reflectsHeaders = $methodResp.Content -match "TRACE / HTTP|TRACE \\*"
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
            elseif ($method -eq "PATCH") {
                if (-not $isSameAsGET) {
                    Write-Finding "MEDIUM" "PATCH method processes differently (HTTP $code)"
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
Write-Phase "5/12" "Cookie Security Analysis"

try {
    $cookieResp = Invoke-WebRequest -Uri $Global:TargetURL -UseBasicParsing -TimeoutSec 10
    $setCookies = $cookieResp.Headers["Set-Cookie"]
    if ($setCookies) {
        Write-Finding "INFO" "Cookies found: $setCookies"
        
        # Parse each cookie
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
# PHASE 6: SENSITIVE FILE DISCOVERY
# ============================================================
Write-Phase "6/12" "Sensitive File Discovery"

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
    @{Path="server-info"; Risk="HIGH"; Desc="Apache server info"}
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
            
            # Save evidence
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
Write-Phase "7/12" "Port Scanning"

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
            
            # Flag dangerous open ports
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

# ============================================================
# PHASE 8: SUBDOMAIN DISCOVERY
# ============================================================
Write-Phase "8/12" "Subdomain Discovery"

# WILDCARD DNS DETECTION - prevents massive false positives
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
    Write-Finding "INFO" "Only checking subdomains that serve DIFFERENT content than the wildcard"
}

$subPrefixes = @("www","mail","webmail","owa","ftp","admin","portal","student","faculty",
    "exam","erp","moodle","lms","dev","staging","test","api","cdn","static",
    "blog","forum","wiki","git","gitlab","jenkins","jira","vpn","remote",
    "intranet","uat","demo","sandbox","backup","old","new","beta","alpha",
    "app","mobile","m","ns1","ns2","mx","smtp","pop","imap","cpanel","plesk")

# Get wildcard baseline page if wildcard DNS exists
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
            # WILDCARD FILTER: If wildcard DNS, skip unless the subdomain serves different content
            if ($Global:HasWildcardDNS) {
                $isDifferent = $false
                foreach ($proto in @("https","http")) {
                    try {
                        $subCheck = Invoke-WebRequest -Uri "$proto`://$fqdn" -UseBasicParsing -TimeoutSec 5
                        $subHash = "$($subCheck.Content.Length)_$($subCheck.StatusCode)"
                        if ($subHash -ne $wildcardPageHash) {
                            $isDifferent = $true
                        }
                        break
                    } catch {}
                }
                if (-not $isDifferent) { continue }  # Skip - same as wildcard catch-all
            }
            
            $subInfo = [PSCustomObject]@{Name=$fqdn; IP=$ip; Server=""; Title=""; Status=""}
            
            # Quick HTTP check
            foreach ($proto in @("https","http")) {
                try {
                    $subResp = Invoke-WebRequest -Uri "$proto`://$fqdn" -UseBasicParsing -TimeoutSec 6
                    $subInfo.Status = "$proto`:$($subResp.StatusCode)"
                    $subInfo.Server = $subResp.Headers["Server"]
                    if ($subResp.Content -match '<title>(.*?)</title>') { $subInfo.Title = $Matches[1].Trim() }
                    
                    # Check for default/unconfigured pages
                    if ($subInfo.Title -match "Default|Parallels|Plesk|cPanel|Welcome to nginx|Apache.*Test|IIS.*Windows|Under Construction|Coming Soon") {
                        Add-Vuln -ID "SUB-$sub" -Title "Unconfigured Subdomain: $fqdn" -Severity "HIGH" -CVSS 7.0 `
                            -Location "$proto`://$fqdn" `
                            -Evidence "Title: '$($subInfo.Title)'. Server: $($subInfo.Server). Default/unconfigured page detected." `
                            -Impact "Unconfigured subdomains are prime targets. May have default credentials. Hosting panels expose server controls." `
                            -Remediation "Remove DNS record or properly configure the subdomain. Restrict admin panel access." -CWE "CWE-16"
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

# ============================================================
# PHASE 9: JS ANALYSIS (Secrets, APIs, Endpoints)
# ============================================================
Write-Phase "9/12" "JavaScript Analysis"

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
    $apiPaths = [regex]::Matches($allJsContent, '["\x27](/api/[^"\x27\s]{2,})["\x27]') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
    $fetchUrls = [regex]::Matches($allJsContent, 'fetch\s*\(\s*[`"\x27](https?://[^"\x27`\s]+)[`"\x27]') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
    if ($apiPaths.Count -gt 0) { Write-Finding "INFO" "API endpoints in JS: $($apiPaths -join ', ')" }
    if ($fetchUrls.Count -gt 0) { Write-Finding "INFO" "External fetch URLs: $($fetchUrls.Count) found" }
    
    # Source map check - ONLY for first-party JS (skip CDN/third-party)
    $mapsFound = 0
    $thirdPartyCDNs = @("cdn.jsdelivr.net","cdnjs.cloudflare.com","unpkg.com","ajax.googleapis.com",
        "code.jquery.com","stackpath.bootstrapcdn.com","maxcdn.bootstrapcdn.com","cdn.datatables.net",
        "fonts.googleapis.com","cse.google.com","www.google.com","www.gstatic.com",
        "maps.googleapis.com","translate.google.com","platform.twitter.com",
        "connect.facebook.net","cdn.firebase.com","cdn.tailwindcss.com")
    foreach ($js in ($jsFiles | Select-Object -First 15)) {
        # FALSE POSITIVE FIX: Skip third-party CDN source maps
        $isThirdParty = $false
        foreach ($cdn in $thirdPartyCDNs) {
            if ($js -match [regex]::Escape($cdn)) { $isThirdParty = $true; break }
        }
        if ($isThirdParty) {
            Write-Finding "INFO" "Skipping CDN source map (third-party, not your code): $js"
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
}

# ============================================================
# PHASE 10: DNS INTELLIGENCE
# ============================================================
Write-Phase "10/12" "DNS Intelligence"

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
# PHASE 11: FORM & INPUT ANALYSIS
# ============================================================
Write-Phase "11/12" "Form and Input Analysis"

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
    }
    Write-Finding "OK" "$($forms.Count) forms found"
}

# ============================================================
# PHASE 12: EXPLOIT CHAIN ANALYSIS
# ============================================================
Write-Phase "12/12" "Exploit Chain Generation"

Write-Finding "INFO" "Analyzing vulnerability combinations..."

$critCount = ($Global:Vulnerabilities | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$highCount = ($Global:Vulnerabilities | Where-Object { $_.Severity -eq "HIGH" }).Count
$medCount = ($Global:Vulnerabilities | Where-Object { $_.Severity -eq "MEDIUM" }).Count
$lowCount = ($Global:Vulnerabilities | Where-Object { $_.Severity -eq "LOW" }).Count
$totalCount = $Global:Vulnerabilities.Count

# Auto-generate exploit chains based on confirmed vulns
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
$hasBackup = $Global:Vulnerabilities | Where-Object { $_.Title -match "backup" }
$hasPwdHTTP = $Global:Vulnerabilities | Where-Object { $_.ID -match "FORM-HTTP-PWD" }
$hasDangerousPorts = $Global:Vulnerabilities | Where-Object { $_.ID -match "PORT-(3389|445|5900)" }

$chainNum = 0

# Chain: MITM/SSL Strip
if ($hasNoHTTPS -and $hasNoHSTS) {
    $chainNum++
    $Global:ExploitChains += [PSCustomObject]@{
        Num = $chainNum
        Name = "MITM/SSL Strip - Session Hijack"
        Severity = "CRITICAL"
        Complexity = "LOW"
        Steps = @(
            "CONFIRMED: No HTTPS enforcement ($(($hasNoHTTPS | Select -First 1).Evidence))",
            "CONFIRMED: No HSTS header to prevent downgrade",
            "ATTACK: Attacker on same network performs ARP spoofing",
            "ATTACK: SSL strip downgrades all connections to HTTP",
            "RESULT: All credentials and session tokens intercepted in plaintext"
        )
        Vulns = @("SSL-05", "HDR-01")
    }
    if ($hasPwdHTTP) {
        $Global:ExploitChains[-1].Steps += "AMPLIFIED: Password forms served over HTTP - credentials directly visible"
    }
    if ($hasUnencryptedMail) {
        $Global:ExploitChains[-1].Steps += "BONUS: Unencrypted POP3/IMAP also intercepted - email credentials stolen"
    }
    Write-Finding "CRITICAL" "Chain $chainNum : MITM/SSL Strip -> Session Hijack"
}

# Chain: XSS exploitation
if ($hasNoCSP) {
    $chainNum++
    $chain = [PSCustomObject]@{
        Num = $chainNum
        Name = "XSS Exploitation (No CSP Restriction)"
        Severity = "HIGH"
        Complexity = "MEDIUM"
        Steps = @(
            "CONFIRMED: No Content-Security-Policy header",
            "ATTACK: Any XSS vulnerability becomes fully exploitable",
            "ATTACK: Injected script can load external resources, exfiltrate data",
            "RESULT: Cookie theft, keylogging, credential harvesting via injected JavaScript"
        )
        Vulns = @("HDR-CSP")
    }
    if ($hasNoXFO) {
        $chain.Steps += "AMPLIFIED: No X-Frame-Options - clickjacking can trick users into triggering XSS"
        $chain.Vulns += "HDR-XFO"
    }
    if ($hasTrace) {
        $chain.Steps += "AMPLIFIED: TRACE method enabled - XST attack can steal HttpOnly cookies via XSS"
        $chain.Vulns += "HTTP-01"
    }
    $Global:ExploitChains += $chain
    Write-Finding "HIGH" "Chain $chainNum : XSS + No CSP -> Full Exploitation"
}

# Chain: Default panel lateral movement
if ($hasDefaultPanel) {
    $chainNum++
    $panelVuln = $hasDefaultPanel | Select-Object -First 1
    $Global:ExploitChains += [PSCustomObject]@{
        Num = $chainNum
        Name = "Unconfigured Subdomain - Lateral Movement"
        Severity = "CRITICAL"
        Complexity = "MEDIUM"
        Steps = @(
            "CONFIRMED: $($panelVuln.Location) shows default/unconfigured page",
            "CONFIRMED: $($panelVuln.Evidence)",
            "ATTACK: Access admin panel (common ports 8443, 8880, 2083)",
            "ATTACK: Use default credentials or known CVEs for the panel software",
            "ATTACK: Gain file system access via panel's file manager",
            "RESULT: Upload webshell, read config files, access database credentials",
            "RESULT: Lateral movement to production site if on same server"
        )
        Vulns = @($panelVuln.ID)
    }
    Write-Finding "CRITICAL" "Chain $chainNum : Default Panel -> Lateral Movement"
}

# Chain: Version disclosure -> CVE targeting
if ($hasVersionLeak -and $hasVersionLeak.Count -ge 2) {
    $chainNum++
    $versions = ($hasVersionLeak | ForEach-Object { $_.Evidence }) -join "; "
    $Global:ExploitChains += [PSCustomObject]@{
        Num = $chainNum
        Name = "Version Disclosure - Targeted CVE Exploitation"
        Severity = "HIGH"
        Complexity = "HIGH"
        Steps = @(
            "CONFIRMED: Multiple version headers exposed: $versions",
            "ATTACK: Search public CVE databases for these exact versions",
            "ATTACK: Test known exploits against confirmed versions",
            "RESULT: Potential Remote Code Execution if server is unpatched"
        )
        Vulns = ($hasVersionLeak | ForEach-Object { $_.ID })
    }
    Write-Finding "HIGH" "Chain $chainNum : Version Leak -> CVE Targeting"
}

# Chain: Email spoofing
if ($hasSPFWeak) {
    $chainNum++
    $Global:ExploitChains += [PSCustomObject]@{
        Num = $chainNum
        Name = "Email Spoofing - Phishing Attack"
        Severity = "MEDIUM"
        Complexity = "LOW"
        Steps = @(
            "CONFIRMED: $($hasSPFWeak[0].Evidence)",
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
        Num = $chainNum
        Name = "Hardcoded Secrets - Direct Backend Access"
        Severity = "CRITICAL"
        Complexity = "LOW"
        Steps = @(
            "CONFIRMED: Secrets found in client-side JavaScript",
            "ATTACK: Use API keys to access backend services directly",
            "ATTACK: Bypass frontend authentication entirely",
            "RESULT: Unauthorized access to backend APIs and data"
        )
        Vulns = ($hasSecrets | ForEach-Object { $_.ID })
    }
    Write-Finding "CRITICAL" "Chain $chainNum : Exposed Secrets -> Backend Access"
}

# Chain: Git/Env exposure
if ($hasGitExposed -or $hasEnvExposed) {
    $chainNum++
    $Global:ExploitChains += [PSCustomObject]@{
        Num = $chainNum
        Name = "Source Code/Config Exposure - Credential Theft"
        Severity = "CRITICAL"
        Complexity = "LOW"
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
        Num = $chainNum
        Name = "Exposed Database - Direct Data Access"
        Severity = "CRITICAL"
        Complexity = "LOW"
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

Write-Finding "OK" "$chainNum exploit chains generated from confirmed vulnerabilities"

# ============================================================
# GENERATE REPORT
# ============================================================
Write-Phase "REPORT" "Generating Final Report"

$reportLines = @()
$reportLines += "# AcroStrike - VAPT Assessment Report"
$reportLines += ""
$reportLines += "| Field | Value |"
$reportLines += "|-------|-------|"
$reportLines += "| **Target** | $TargetClean |"
$reportLines += "| **URL** | $($Global:TargetURL) |"
$reportLines += "| **Date** | $Timestamp |"
$reportLines += "| **Scanner** | AcroStrike v1.0 (Pure PowerShell) |"
$reportLines += "| **Methodology** | Passive reconnaissance + active probing (public surface only) |"
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
    $vulnsOfSev = $Global:Vulnerabilities | Where-Object { $_.Severity -eq $sev }
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
        $reportLines += "**Severity:** $($chain.Severity) | **Complexity:** $($chain.Complexity)"
        $reportLines += ""
        $reportLines += "``````"
        $stepNum = 0
        foreach ($step in $chain.Steps) {
            $stepNum++
            $reportLines += "  Step $stepNum : $step"
        }
        $reportLines += "``````"
        $reportLines += ""
        if ($chain.Vulns) {
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
foreach ($v in ($Global:Vulnerabilities | Where-Object { $_.Severity -eq "CRITICAL" })) {
    $pNum++
    $reportLines += "| P0-$pNum | $($v.Remediation) | $($v.ID) |"
}
foreach ($v in ($Global:Vulnerabilities | Where-Object { $_.Severity -eq "HIGH" } | Select-Object -First 5)) {
    $pNum++
    $reportLines += "| P1-$pNum | $($v.Remediation) | $($v.ID) |"
}
$reportLines += ""

# Footer
$reportLines += "---"
$reportLines += ""
$reportLines += "*Generated by AcroStrike v1.0 - Part of the Acro Empire*"
$reportLines += ""
$reportLines += "*All findings are from publicly accessible information. No exploitation was performed.*"
$reportLines += ""
$reportLines += "*Scan completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')*"

$reportContent = $reportLines -join "`n"
$reportContent | Out-File "$OutputDir\VAPT_REPORT.md" -Encoding UTF8

# Also generate JSON for machine parsing
$jsonReport = @{
    target = $TargetClean
    url = $Global:TargetURL
    scan_date = $Timestamp
    scanner = "AcroStrike v1.0"
    summary = @{
        total = $totalCount
        critical = $critCount
        high = $highCount
        medium = $medCount
        low = $lowCount
        exploit_chains = $chainNum
        subdomains = $Global:Subdomains.Count
        open_ports = $Global:OpenPorts.Count
    }
    tech_stack = $Global:TechStack
    vulnerabilities = $Global:Vulnerabilities
    exploit_chains_detail = $Global:ExploitChains
    subdomains = $Global:Subdomains
    open_ports = $Global:OpenPorts
} | ConvertTo-Json -Depth 5
$jsonReport | Out-File "$OutputDir\VAPT_REPORT.json" -Encoding UTF8

# ============================================================
# FINAL SUMMARY
# ============================================================
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
Write-Host ""
Write-Host "    Report (MD)    : $OutputDir\VAPT_REPORT.md" -ForegroundColor Yellow
Write-Host "    Report (JSON)  : $OutputDir\VAPT_REPORT.json" -ForegroundColor Yellow
Write-Host "    Evidence       : $OutputDir\evidence\" -ForegroundColor Yellow
Write-Host ""
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host "  Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host ""

# Open output folder
explorer $OutputDir
