# Simple PFX Creator - Uses modern PowerShell methods
# Creates PFX from PEM certificate and key files

param(
    [string]$LocalPath = "C:\Users\south\Documents\technitium-setup\certificates",
    [string]$DomainName = "dns.netintegrate.net",
    [string]$Password = "netintegrate"
)

$ErrorActionPreference = "Continue"

Write-Host "`n=== Simple PFX Creator ===" -ForegroundColor Cyan

$certFile = Join-Path $LocalPath "$DomainName.full_chain.pem"
$keyFile = Join-Path $LocalPath "$DomainName.key"
$pfxFile = Join-Path $LocalPath "dns.netintegrate.net_full_chain.pfx"

Write-Host "`n[STEP 1] Checking input files..." -ForegroundColor Yellow

if (-not (Test-Path $certFile)) {
    Write-Host "  ✗ Certificate file not found: $certFile" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $keyFile)) {
    Write-Host "  ✗ Private key file not found: $keyFile" -ForegroundColor Red
    exit 1
}

Write-Host "  ✓ Certificate file: $(Split-Path $certFile -Leaf)" -ForegroundColor Green
Write-Host "  ✓ Private key file: $(Split-Path $keyFile -Leaf)" -ForegroundColor Green

Write-Host "`n[STEP 2] Loading certificate data..." -ForegroundColor Yellow

$certContent = Get-Content $certFile -Raw
$keyContent = Get-Content $keyFile -Raw

Write-Host "  ✓ Certificate content: $($certContent.Length) characters" -ForegroundColor Green
Write-Host "  ✓ Private key content: $($keyContent.Length) characters" -ForegroundColor Green

Write-Host "`n[STEP 3] Using .NET 5+ certificate methods..." -ForegroundColor Yellow

try {
    # Use the modern CreateFromPem method (available in .NET 5+)
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($certContent, $keyContent)
    
    Write-Host "  ✓ Certificate created from PEM data" -ForegroundColor Green
    Write-Host "    Subject: $($certificate.Subject)" -ForegroundColor Gray
    Write-Host "    Issuer: $($certificate.Issuer)" -ForegroundColor Gray
    Write-Host "    Valid From: $($certificate.NotBefore)" -ForegroundColor Gray
    Write-Host "    Valid To: $($certificate.NotAfter)" -ForegroundColor Gray
    Write-Host "    Has Private Key: $($certificate.HasPrivateKey)" -ForegroundColor $(if($certificate.HasPrivateKey) { 'Green' } else { 'Red' })
}
catch {
    Write-Host "  ✗ CreateFromPem failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "`n  → Trying alternative method..." -ForegroundColor Yellow
    
    try {
        # Alternative: Import certificate separately and try to associate key
        $certBytes = [System.Text.Encoding]::UTF8.GetBytes($certContent)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
        
        Write-Host "    ✓ Certificate imported (without private key)" -ForegroundColor Yellow
        Write-Host "    Subject: $($certificate.Subject)" -ForegroundColor Gray
        
        # Note: Private key association is complex without CreateFromPem
        Write-Host "    ⚠ Private key association not available in older .NET" -ForegroundColor Yellow
    }
    catch {
        Write-Host "    ✗ Alternative method failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "`n  → Checking .NET version..." -ForegroundColor Yellow
        
        $dotnetVersion = $PSVersionTable.PSVersion
        Write-Host "    PowerShell Version: $dotnetVersion" -ForegroundColor Gray
        Write-Host "    .NET Framework may not support CreateFromPem" -ForegroundColor Yellow
        
        # Final fallback - manual file creation
        Write-Host "`n  → Using manual approach..." -ForegroundColor Cyan
        
        # Try to create a temporary combined file for Windows cert store
        $tempCombined = Join-Path $LocalPath "temp_combined.pem"
        $combinedContent = $certContent + "`n" + $keyContent
        $combinedContent | Out-File -FilePath $tempCombined -Encoding UTF8 -Force
        
        Write-Host "    ✓ Created temporary combined file" -ForegroundColor Green
        
        # This won't create the PFX but shows the data is available
        $certificate = $null
    }
}

Write-Host "`n[STEP 4] Creating PFX file..." -ForegroundColor Yellow

if ($certificate -and $certificate.HasPrivateKey) {
    try {
        # Export to PFX with password
        $pfxBytes = $certificate.Export('Pkcs12', $Password)
        [System.IO.File]::WriteAllBytes($pfxFile, $pfxBytes)
        
        if (Test-Path $pfxFile) {
            $pfxSize = [math]::Round((Get-Item $pfxFile).Length/1KB, 2)
            Write-Host "  ✓ PFX file created: $pfxSize KB" -ForegroundColor Green
            Write-Host "    Path: $pfxFile" -ForegroundColor Gray
        }
        else {
            Write-Host "  ✗ PFX file was not created" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "  ✗ PFX export failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}
else {
    Write-Host "  ⚠ Cannot create PFX - certificate lacks private key or is null" -ForegroundColor Yellow
    
    Write-Host "`n  Alternative solutions:" -ForegroundColor Cyan
    Write-Host "  1. Install OpenSSL for Windows" -ForegroundColor White
    Write-Host "  2. Use cert-manager GUI at http://192.168.0.251:3000" -ForegroundColor White
    Write-Host "  3. Use Windows Certificate MMC snap-in" -ForegroundColor White
    Write-Host "  4. Install WSL with OpenSSL" -ForegroundColor White
}

Write-Host "`n[STEP 5] WSL OpenSSL attempt..." -ForegroundColor Yellow

try {
    # Check if WSL is available
    $wslCheck = & wsl --list --quiet 2>$null
    if ($wslCheck) {
        Write-Host "  ✓ WSL detected, attempting OpenSSL..." -ForegroundColor Green
        
        # Convert Windows paths to WSL paths
        $wslCertFile = "/mnt/c" + $certFile.Replace("C:", "").Replace("\", "/")
        $wslKeyFile = "/mnt/c" + $keyFile.Replace("C:", "").Replace("\", "/")
        $wslPfxFile = "/mnt/c" + $pfxFile.Replace("C:", "").Replace("\", "/")
        
        # Run OpenSSL in WSL
        $wslCommand = "openssl pkcs12 -export -out '$wslPfxFile' -inkey '$wslKeyFile' -in '$wslCertFile' -password pass:$Password"
        
        $wslResult = & wsl bash -c $wslCommand 2>&1
        
        if (Test-Path $pfxFile) {
            $pfxSize = [math]::Round((Get-Item $pfxFile).Length/1KB, 2)
            Write-Host "  ✓ WSL OpenSSL success: $pfxSize KB" -ForegroundColor Green
        }
        else {
            Write-Host "  ✗ WSL OpenSSL failed" -ForegroundColor Red
            Write-Host "    Output: $wslResult" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "  → WSL not available" -ForegroundColor Gray
    }
}
catch {
    Write-Host "  → WSL OpenSSL not available: $($_.Exception.Message)" -ForegroundColor Gray
}

# Final status check
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SIMPLE PFX CREATOR COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if (Test-Path $pfxFile) {
    Write-Host "`n🎉 SUCCESS: PFX file created successfully!" -ForegroundColor Green
else {
    Write-Host "`n📋 NEXT STEPS:" -ForegroundColor Yellow
    Write-Host "1. Visit cert-manager GUI: http://192.168.0.251:3000" -ForegroundColor White
    Write-Host "2. Find the dns.netintegrate.net certificate" -ForegroundColor White
    Write-Host "3. Download it in PFX/P12 format" -ForegroundColor White
    Write-Host "4. Save as 'dns.netintegrate.net_full_chain.pfx'" -ForegroundColor White
    Write-Host "5. Use password: $Password" -ForegroundColor White
}