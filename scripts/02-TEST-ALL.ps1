# Comprehensive Test Suite for Technitium DNS Setup
# Tests all components and services

param(
    [string]$DNSServer = "192.168.0.252",
    [string]$CAServer = "192.168.0.251",
    [string]$CertificatePath = "C:\Users\south\Documents\technitium-setup\certificates"
)

$ErrorActionPreference = "Continue"

Write-Host "`n=== Comprehensive Technitium DNS Test Suite ===" -ForegroundColor Cyan

# Test Results Tracking
$TestResults = @()

function Add-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Details = ""
    )
    
    $TestResults += [PSCustomObject]@{
        Test = $TestName
        Status = if($Passed) { "PASS" } else { "FAIL" }
        Details = $Details
        Timestamp = Get-Date
    }
    
    $color = if($Passed) { "Green" } else { "Red" }
    $symbol = if($Passed) { "✓" } else { "✗" }
    Write-Host "  $symbol $TestName" -ForegroundColor $color
    if($Details) {
        Write-Host "    $Details" -ForegroundColor Gray
    }
}

# Test 1: Certificate Files
Write-Host "`n[TEST SUITE 1] Certificate Files" -ForegroundColor Yellow

$requiredCerts = @(
    "dns.netintegrate.net_full_chain.pfx",
    "dns2.netintegrate.net_full_chain.pfx"
)

foreach($cert in $requiredCerts) {
    $certPath = Join-Path $CertificatePath $cert
    if(Test-Path $certPath) {
        $fileInfo = Get-Item $certPath
        Add-TestResult "Certificate Exists: $cert" $true "Size: $([math]::Round($fileInfo.Length/1KB, 2)) KB"
        
        # Test PFX validity
        try {
            $password = if($cert -like "*dns2*") { "" } else { "netintegrate" }
            $testCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath, $password)
            $hasPrivateKey = $testCert.HasPrivateKey
            Add-TestResult "Certificate Valid: $cert" $hasPrivateKey "Has Private Key: $hasPrivateKey"
            $testCert.Dispose()
        }
        catch {
            Add-TestResult "Certificate Valid: $cert" $false "Error: $($_.Exception.Message)"
        }
    }
    else {
        Add-TestResult "Certificate Exists: $cert" $false "File not found: $certPath"
    }
}

# Test 2: Certificate Authority
Write-Host "`n[TEST SUITE 2] Certificate Authority Services" -ForegroundColor Yellow

try {
    $caResponse = Invoke-RestMethod -Uri "http://$CAServer:8000" -TimeoutSec 10
    Add-TestResult "CA FastAPI Backend" $true "Version: $($caResponse.version)"
}
catch {
    Add-TestResult "CA FastAPI Backend" $false "Error: $($_.Exception.Message)"
}

try {
    $guiResponse = Invoke-WebRequest -Uri "http://$CAServer:3000" -TimeoutSec 10 -UseBasicParsing
    Add-TestResult "CA Management GUI" ($guiResponse.StatusCode -eq 200) "Status: $($guiResponse.StatusCode)"
}
catch {
    Add-TestResult "CA Management GUI" $false "Error: $($_.Exception.Message)"
}

# Test 3: DNS Server Connectivity
Write-Host "`n[TEST SUITE 3] DNS Server Connectivity" -ForegroundColor Yellow

# Test basic connectivity
try {
    $ping = Test-Connection -ComputerName $DNSServer -Count 2 -Quiet
    Add-TestResult "DNS Server Ping" $ping "Server: $DNSServer"
}
catch {
    Add-TestResult "DNS Server Ping" $false "Server unreachable: $DNSServer"
}

# Test DNS port 53
try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $asyncResult = $tcpClient.BeginConnect($DNSServer, 53, $null, $null)
    $wait = $asyncResult.AsyncWaitHandle.WaitOne(3000)
    if($wait) {
        $tcpClient.EndConnect($asyncResult)
        Add-TestResult "DNS Port 53 TCP" $true "Port open"
        $tcpClient.Close()
    }
    else {
        Add-TestResult "DNS Port 53 TCP" $false "Connection timeout"
    }
}
catch {
    Add-TestResult "DNS Port 53 TCP" $false "Error: $($_.Exception.Message)"
}

# Test web console port
try {
    $webResponse = Invoke-WebRequest -Uri "http://$DNSServer:5380" -TimeoutSec 10 -UseBasicParsing
    Add-TestResult "DNS Web Console" ($webResponse.StatusCode -eq 200) "Status: $($webResponse.StatusCode)"
}
catch {
    Add-TestResult "DNS Web Console" $false "Error: $($_.Exception.Message)"
}

# Test 4: DNS Resolution
Write-Host "`n[TEST SUITE 4] DNS Resolution Tests" -ForegroundColor Yellow

# Test basic DNS resolution
try {
    $dnsResult = Resolve-DnsName -Name "google.com" -Server $DNSServer -Type A -ErrorAction Stop
    Add-TestResult "Basic DNS Resolution" $true "Resolved to: $($dnsResult[0].IPAddress)"
}
catch {
    Add-TestResult "Basic DNS Resolution" $false "Error: $($_.Exception.Message)"
}

# Test DNSSEC resolution
try {
    $dnssecResult = Resolve-DnsName -Name "cloudflare.com" -Server $DNSServer -DnssecOk -ErrorAction Stop
    $hasDnssec = $dnssecResult | Where-Object { $_.Type -eq "RRSIG" }
    Add-TestResult "DNSSEC Resolution" ($hasDnssec -ne $null) "DNSSEC records found: $($hasDnssec -ne $null)"
}
catch {
    Add-TestResult "DNSSEC Resolution" $false "Error: $($_.Exception.Message)"
}

# Test 5: Secure DNS Protocols
Write-Host "`n[TEST SUITE 5] Secure DNS Protocol Tests" -ForegroundColor Yellow

# Test DoT (DNS over TLS) - Port 853
try {
    $dotClient = New-Object System.Net.Sockets.TcpClient
    $asyncResult = $dotClient.BeginConnect($DNSServer, 853, $null, $null)
    $wait = $asyncResult.AsyncWaitHandle.WaitOne(3000)
    if($wait) {
        $dotClient.EndConnect($asyncResult)
        Add-TestResult "DNS-over-TLS Port" $true "Port 853 open"
        $dotClient.Close()
    }
    else {
        Add-TestResult "DNS-over-TLS Port" $false "Port 853 timeout"
    }
}
catch {
    Add-TestResult "DNS-over-TLS Port" $false "Error: $($_.Exception.Message)"
}

# Test DoH (DNS over HTTPS) - Port 443
try {
    $dohClient = New-Object System.Net.Sockets.TcpClient
    $asyncResult = $dohClient.BeginConnect($DNSServer, 443, $null, $null)
    $wait = $asyncResult.AsyncWaitHandle.WaitOne(3000)
    if($wait) {
        $dohClient.EndConnect($asyncResult)
        Add-TestResult "DNS-over-HTTPS Port" $true "Port 443 open"
        $dohClient.Close()
    }
    else {
        Add-TestResult "DNS-over-HTTPS Port" $false "Port 443 timeout"
    }
}
catch {
    Add-TestResult "DNS-over-HTTPS Port" $false "Error: $($_.Exception.Message)"
}

# Test 6: PowerShell Module Dependencies
Write-Host "`n[TEST SUITE 6] PowerShell Module Dependencies" -ForegroundColor Yellow

$requiredModules = @(
    "Posh-SSH",
    "Microsoft.PowerShell.SecretManagement"
)

foreach($module in $requiredModules) {
    $moduleInstalled = Get-Module -Name $module -ListAvailable
    Add-TestResult "Module: $module" ($moduleInstalled -ne $null) "Version: $($moduleInstalled.Version -join ', ')"
}

# Test 7: Network Configuration
Write-Host "`n[TEST SUITE 7] Network Configuration" -ForegroundColor Yellow

# Test firewall rules (Windows)
if($IsWindows -or $PSVersionTable.PSVersion.Major -lt 6) {
    try {
        $firewallRules = Get-NetFirewallRule -DisplayName "*DNS*" -ErrorAction SilentlyContinue
        Add-TestResult "DNS Firewall Rules" ($firewallRules.Count -gt 0) "Found $($firewallRules.Count) DNS-related rules"
    }
    catch {
        Add-TestResult "DNS Firewall Rules" $false "Cannot check firewall rules"
    }
}

# Test local DNS configuration
try {
    $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses -contains $DNSServer }
    Add-TestResult "Local DNS Configuration" ($dnsServers -ne $null) "DNS server configured locally: $($dnsServers -ne $null)"
}
catch {
    Add-TestResult "Local DNS Configuration" $false "Cannot check local DNS config"
}

# Test 8: Certificate Expiration
Write-Host "`n[TEST SUITE 8] Certificate Expiration Check" -ForegroundColor Yellow

foreach($cert in $requiredCerts) {
    $certPath = Join-Path $CertificatePath $cert
    if(Test-Path $certPath) {
        try {
            $password = if($cert -like "*dns2*") { "" } else { "netintegrate" }
            $testCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath, $password)
            
            $daysUntilExpiry = ($testCert.NotAfter - (Get-Date)).Days
            $isValid = $daysUntilExpiry -gt 30  # Warn if less than 30 days
            
            Add-TestResult "Certificate Expiry: $cert" $isValid "Expires in $daysUntilExpiry days ($($testCert.NotAfter))"
            $testCert.Dispose()
        }
        catch {
            Add-TestResult "Certificate Expiry: $cert" $false "Cannot read certificate"
        }
    }
}

# Test 9: System Resources
Write-Host "`n[TEST SUITE 9] System Resources" -ForegroundColor Yellow

# Check available disk space
$certificateDrive = Split-Path $CertificatePath -Qualifier
try {
    $driveInfo = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$certificateDrive'" -ErrorAction SilentlyContinue
    if($driveInfo) {
        $freeSpaceGB = [math]::Round($driveInfo.FreeSpace / 1GB, 2)
        $hasSpace = $freeSpaceGB -gt 1  # At least 1GB free
        Add-TestResult "Disk Space" $hasSpace "Free space: $freeSpaceGB GB on $certificateDrive"
    }
}
catch {
    Add-TestResult "Disk Space" $false "Cannot check disk space"
}

# Check memory usage
try {
    $memory = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
    if($memory) {
        $totalMemoryGB = [math]::Round($memory.TotalPhysicalMemory / 1GB, 2)
        $hasMemory = $totalMemoryGB -gt 2  # At least 2GB RAM
        Add-TestResult "System Memory" $hasMemory "Total RAM: $totalMemoryGB GB"
    }
}
catch {
    Add-TestResult "System Memory" $false "Cannot check system memory"
}

# Generate Test Report
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TEST SUITE COMPLETE" -ForegroundColor Cyan  
Write-Host "========================================" -ForegroundColor Cyan

$totalTests = $TestResults.Count
$passedTests = ($TestResults | Where-Object { $_.Status -eq "PASS" }).Count
$failedTests = $totalTests - $passedTests
$successRate = [math]::Round(($passedTests / $totalTests) * 100, 1)

Write-Host "`nSUMMARY:" -ForegroundColor White
Write-Host "  Total Tests: $totalTests" -ForegroundColor Gray
Write-Host "  Passed: $passedTests" -ForegroundColor Green
Write-Host "  Failed: $failedTests" -ForegroundColor Red
Write-Host "  Success Rate: $successRate%" -ForegroundColor $(if($successRate -ge 80) { 'Green' } else { 'Yellow' })

# Show failed tests
if($failedTests -gt 0) {
    Write-Host "`nFAILED TESTS:" -ForegroundColor Red
    $TestResults | Where-Object { $_.Status -eq "FAIL" } | ForEach-Object {
        Write-Host "  ✗ $($_.Test)" -ForegroundColor Red
        if($_.Details) {
            Write-Host "    $($_.Details)" -ForegroundColor Gray
        }
    }
}

# Export detailed report
$reportFile = Join-Path $CertificatePath "test-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
try {
    $TestResults | ConvertTo-Json -Depth 3 | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "`n📄 Detailed report saved: $reportFile" -ForegroundColor Cyan
}
catch {
    Write-Host "`n⚠ Could not save detailed report" -ForegroundColor Yellow
}

# Overall Status
Write-Host "`n🎯 OVERALL STATUS:" -ForegroundColor White
if($successRate -ge 90) {
    Write-Host "🎉 EXCELLENT - System is ready for production!" -ForegroundColor Green
}
elseif($successRate -ge 80) {
    Write-Host "✅ GOOD - Minor issues may need attention" -ForegroundColor Yellow
}
elseif($successRate -ge 60) {
    Write-Host "⚠ FAIR - Several issues need to be resolved" -ForegroundColor Yellow
}
else {
    Write-Host "❌ POOR - Major issues require immediate attention" -ForegroundColor Red
}

Write-Host "`n📞 Next Steps:" -ForegroundColor Cyan
Write-Host "1. Address any failed tests above" -ForegroundColor White
Write-Host "2. Run troubleshooting scripts for specific issues" -ForegroundColor White
Write-Host "3. Verify DNS server configuration" -ForegroundColor White
Write-Host "4. Test secure DNS functionality" -ForegroundColor White

return $successRate