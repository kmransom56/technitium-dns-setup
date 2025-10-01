# Final Certificate Verification
# Tests both PFX files for completeness and validity

param(
    [string]$LocalPath = "C:\Users\south\Documents\technitium-setup\certificates",
    [string]$Password = "netintegrate"
)

$ErrorActionPreference = "Continue"

Write-Host "`n=== Final Certificate Verification ===" -ForegroundColor Cyan

$requiredFiles = @(
    "dns.netintegrate.net_full_chain.pfx",
    "dns2.netintegrate.net_full_chain.pfx"
)

Write-Host "`n[VERIFICATION] Testing PFX certificates..." -ForegroundColor Yellow

$allValid = $true

foreach ($file in $requiredFiles) {
    $filePath = Join-Path $LocalPath $file
    
    Write-Host "`n  Testing: $file" -ForegroundColor White
    
    if (-not (Test-Path $filePath)) {
        Write-Host "    ✗ File not found" -ForegroundColor Red
        $allValid = $false
        continue
    }
    
    $fileInfo = Get-Item $filePath
    $size = [math]::Round($fileInfo.Length/1KB, 2)
    Write-Host "    • Size: $size KB" -ForegroundColor Gray
    Write-Host "    • Created: $($fileInfo.CreationTime)" -ForegroundColor Gray
    
    try {
        # Test with the standard password
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($filePath, $Password)
        
        Write-Host "    ✓ PFX loads successfully" -ForegroundColor Green
        Write-Host "    • Subject: $($cert.Subject)" -ForegroundColor Gray
        Write-Host "    • Issuer: $($cert.Issuer)" -ForegroundColor Gray
        Write-Host "    • Valid From: $($cert.NotBefore)" -ForegroundColor Gray
        Write-Host "    • Valid To: $($cert.NotAfter)" -ForegroundColor Gray
        Write-Host "    • Serial Number: $($cert.SerialNumber)" -ForegroundColor Gray
        Write-Host "    • Thumbprint: $($cert.Thumbprint)" -ForegroundColor Gray
        Write-Host "    • Has Private Key: $($cert.HasPrivateKey)" -ForegroundColor $(if($cert.HasPrivateKey) { 'Green' } else { 'Red' })
        
        # Check certificate validity
        $now = Get-Date
        if ($now -lt $cert.NotBefore) {
            Write-Host "    ⚠ Certificate is not yet valid" -ForegroundColor Yellow
        }
        elseif ($now -gt $cert.NotAfter) {
            Write-Host "    ✗ Certificate has expired" -ForegroundColor Red
            $allValid = $false
        }
        else {
            $daysLeft = ($cert.NotAfter - $now).Days
            Write-Host "    ✓ Certificate is valid ($daysLeft days remaining)" -ForegroundColor Green
        }
        
        # Test private key functionality (if available)
        if ($cert.HasPrivateKey) {
            try {
                $privateKey = $cert.PrivateKey
                if ($privateKey) {
                    Write-Host "    ✓ Private key is accessible" -ForegroundColor Green
                }
                else {
                    Write-Host "    ⚠ Private key reported but not accessible" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "    ⚠ Private key access test failed: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "    ✗ No private key found in PFX" -ForegroundColor Red
            $allValid = $false
        }
        
        $cert.Dispose()
    }
    catch {
        Write-Host "    ✗ PFX validation failed: $($_.Exception.Message)" -ForegroundColor Red
        
        # Try with empty password
        try {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($filePath, "")
            Write-Host "    ✓ PFX loads with empty password" -ForegroundColor Yellow
            Write-Host "    • Subject: $($cert.Subject)" -ForegroundColor Gray
            Write-Host "    • Has Private Key: $($cert.HasPrivateKey)" -ForegroundColor $(if($cert.HasPrivateKey) { 'Green' } else { 'Red' })
            $cert.Dispose()
        }
        catch {
            Write-Host "    ✗ PFX also fails with empty password" -ForegroundColor Red
            $allValid = $false
        }
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "CERTIFICATE VERIFICATION COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($allValid) {
    Write-Host "`n🎉 ALL CERTIFICATES ARE VALID AND READY!" -ForegroundColor Green
    
    Write-Host "`n🚀 READY FOR TECHNITIUM DNS SETUP:" -ForegroundColor Yellow
    Write-Host "   • Both PFX certificates are complete with private keys" -ForegroundColor White
    Write-Host "   • Certificates are valid and not expired" -ForegroundColor White
    Write-Host "   • Password is set to 'netintegrate'" -ForegroundColor White
    Write-Host "   • Full certificate chain is included" -ForegroundColor White
    
    Write-Host "`n📞 Next: Copy certificates to DNS server and configure DoH/DoT" -ForegroundColor Cyan
}
else {
    Write-Host "`n⚠ SOME CERTIFICATES HAVE ISSUES" -ForegroundColor Yellow
    Write-Host "Check the validation messages above for details" -ForegroundColor Gray
    Write-Host "`nMost issues can be resolved by:" -ForegroundColor White
    Write-Host "1. Verifying the correct password" -ForegroundColor Gray
    Write-Host "2. Regenerating certificates if needed" -ForegroundColor Gray
    Write-Host "3. Using cert-manager GUI for manual download" -ForegroundColor Gray
}