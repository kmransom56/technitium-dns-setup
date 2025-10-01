# Working FastAPI Certificate Generator
# Uses the correct cert-manager API schema format

param(
    [string]$CAServer = "192.168.0.251",
    [string]$LocalPath = "C:\Users\south\Documents\technitium-setup\certificates",
    [string]$DomainName = "dns.netintegrate.net",
    [string]$ApiPort = "8000"
)

$ErrorActionPreference = "Continue"

Write-Host "`n=== Working FastAPI Certificate Generator ===" -ForegroundColor Cyan

# Step 1: Connect to FastAPI backend
Write-Host "`n[STEP 1] Connecting to cert-manager FastAPI backend..." -ForegroundColor Yellow

$baseUrl = "http://$CAServer`:$ApiPort"
Write-Host "  API Base URL: $baseUrl" -ForegroundColor Gray

try {
    $apiInfo = Invoke-RestMethod -Uri $baseUrl -Method GET -UseBasicParsing
    Write-Host "  ✓ Connected to: $($apiInfo.name) v$($apiInfo.version)" -ForegroundColor Green
    Write-Host "    Documentation: $baseUrl/docs" -ForegroundColor Cyan
}
catch {
    Write-Host "  ✗ Failed to connect: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Step 2: Prepare certificate request using correct schema
Write-Host "`n[STEP 2] Preparing certificate request..." -ForegroundColor Yellow

$certRequest = @{
    serverName = $DomainName
    serverIp = $null
    caPassword = $null
    certificateType = "server"
    outputFormat = "pem"
    keySize = 2048
    validityDays = 365
    includeContent = $true
}

Write-Host "  Certificate request details:" -ForegroundColor White
Write-Host "    Server Name: $($certRequest.serverName)" -ForegroundColor Gray
Write-Host "    Certificate Type: $($certRequest.certificateType)" -ForegroundColor Gray
Write-Host "    Output Format: $($certRequest.outputFormat)" -ForegroundColor Gray
Write-Host "    Key Size: $($certRequest.keySize) bits" -ForegroundColor Gray
Write-Host "    Validity: $($certRequest.validityDays) days" -ForegroundColor Gray
Write-Host "    Include Content: $($certRequest.includeContent)" -ForegroundColor Gray

# Step 3: Generate certificate
Write-Host "`n[STEP 3] Generating certificate..." -ForegroundColor Yellow

$generateUrl = "$baseUrl/api/generate-cert"
$headers = @{
    "Content-Type" = "application/json"
    "Accept" = "application/json"
}

try {
    $requestBody = $certRequest | ConvertTo-Json -Depth 10
    
    Write-Host "  Sending request to: $generateUrl" -ForegroundColor Gray
    Write-Host "  Request body: $requestBody" -ForegroundColor DarkGray
    
    $response = Invoke-RestMethod -Uri $generateUrl -Method POST -Body $requestBody -Headers $headers -TimeoutSec 60
    
    if ($response) {
        Write-Host "  ✓ Certificate generation successful!" -ForegroundColor Green
        
        # Display response structure
        Write-Host "`n  Response contains:" -ForegroundColor White
        $response.PSObject.Properties | ForEach-Object {
            Write-Host "    • $($_.Name): $($_.Value.GetType().Name)" -ForegroundColor Gray
        }
        
        # Extract certificate data
        $certificateGenerated = $false
        
        # Check for certificate content in response
        if ($response.certificate) {
            Write-Host "`n  ✓ Certificate content found in response" -ForegroundColor Green
            
            $certPath = Join-Path $LocalPath "$DomainName.crt"
            $response.certificate | Out-File -FilePath $certPath -Encoding UTF8 -Force
            Write-Host "    Saved certificate: $DomainName.crt" -ForegroundColor Green
            $certificateGenerated = $true
        }
        
        if ($response.private_key) {
            Write-Host "  ✓ Private key found in response" -ForegroundColor Green
            
            $keyPath = Join-Path $LocalPath "$DomainName.key"
            $response.private_key | Out-File -FilePath $keyPath -Encoding UTF8 -Force
            Write-Host "    Saved private key: $DomainName.key" -ForegroundColor Green
        }
        
        if ($response.p12_content -or $response.pfx_content) {
            Write-Host "  ✓ P12/PFX content found in response" -ForegroundColor Green
            
            $p12Data = $response.p12_content ?? $response.pfx_content
            $pfxPath = Join-Path $LocalPath "dns.netintegrate.net_full_chain.pfx"
            
            try {
                # Handle base64 encoded P12 data
                $p12Bytes = [System.Convert]::FromBase64String($p12Data)
                [System.IO.File]::WriteAllBytes($pfxPath, $p12Bytes)
                Write-Host "    Saved PFX: dns.netintegrate.net_full_chain.pfx" -ForegroundColor Green
                $certificateGenerated = $true
            }
            catch {
                Write-Host "    ⚠ Failed to decode P12 data: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        
        # Show full response for debugging
        Write-Host "`n  Full API response:" -ForegroundColor White
        Write-Host "  $($response | ConvertTo-Json -Depth 3)" -ForegroundColor DarkGray
        
    }
    else {
        Write-Host "  ✗ No response received" -ForegroundColor Red
    }
}
catch {
    Write-Host "  ✗ Certificate generation failed: $($_.Exception.Message)" -ForegroundColor Red
    
    if ($_.Exception.Response) {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-Host "    HTTP Status: $statusCode" -ForegroundColor Gray
        
        if ($statusCode -eq 422) {
            Write-Host "    This is a validation error - check the API documentation" -ForegroundColor Yellow
        }
    }
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "CERTIFICATE GENERATION COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "API Server: $baseUrl" -ForegroundColor White
Write-Host "Target Domain: $DomainName" -ForegroundColor White
Write-Host "Certificate Directory: $LocalPath" -ForegroundColor White