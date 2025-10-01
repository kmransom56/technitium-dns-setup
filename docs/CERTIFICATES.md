# Certificate Management for Technitium DNS

## Overview

Technitium DNS Server supports TLS certificates for:
- **DNS-over-HTTPS (DoH)** - Port 443
- **DNS-over-TLS (DoT)** - Port 853
- **Web Console HTTPS** - Port 5380

## Certificate Requirements

### Format Requirements
- **PFX/PKCS#12 format** (.pfx or .p12)
- **Contains private key** and certificate chain
- **Password protected** (recommended)
- **Valid certificate chain** to trusted root CA

### Domain Requirements
- **Subject Alternative Names (SAN)** must include:
  - Server FQDN (e.g., `dns.example.com`)
  - Server IP address (optional)
- **Valid for intended use** (TLS Server Authentication)
- **Not expired** and valid date range

## Certificate Sources

### 1. Let's Encrypt (Recommended)

```bash
# Install Certbot
sudo apt-get install certbot

# Generate certificate (HTTP challenge)
sudo certbot certonly --standalone -d dns.example.com

# Convert to PFX format
sudo openssl pkcs12 -export \
  -out /etc/letsencrypt/live/dns.example.com/dns.pfx \
  -inkey /etc/letsencrypt/live/dns.example.com/privkey.pem \
  -in /etc/letsencrypt/live/dns.example.com/fullchain.pem \
  -password pass:your-secure-password
```

### 2. Internal Certificate Authority

#### Using our cert-manager setup:

```powershell
# Generate certificate using our scripts
.\scripts\16-WORKING-CERT-GEN.ps1 -DomainName "dns.example.com"

# Create PFX file
.\scripts\19-SIMPLE-PFX.ps1 -DomainName "dns.example.com" -Password "secure-password"
```

#### Manual CA setup:

```bash
# Generate private key
openssl genrsa -out ca.key 4096

# Generate root certificate
openssl req -new -x509 -key ca.key -sha256 -subj "/C=US/ST=State/L=City/O=Organization/CN=Root CA" -days 3650 -out ca.crt

# Generate server private key
openssl genrsa -out dns.key 2048

# Generate certificate signing request
openssl req -new -key dns.key -out dns.csr -subj "/C=US/ST=State/L=City/O=Organization/CN=dns.example.com"

# Generate server certificate
openssl x509 -req -in dns.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out dns.crt -days 365 -sha256

# Create PFX bundle
openssl pkcs12 -export -out dns.pfx -inkey dns.key -in dns.crt -certfile ca.crt -password pass:secure-password
```

### 3. Commercial Certificate Authority

1. **Purchase certificate** from trusted CA (DigiCert, GlobalSign, etc.)
2. **Generate CSR** with proper Subject Alternative Names
3. **Complete validation** process
4. **Download certificate** and private key
5. **Convert to PFX** format if necessary

## Certificate Installation

### Via Web Console

1. **Access Web Console**: `http://your-dns-server:5380`
2. **Navigate to**: Settings → Certificates
3. **Click**: Import Certificate
4. **Select**: PFX file
5. **Enter**: Certificate password
6. **Click**: Import

### Via PowerShell Script

```powershell
# Copy certificate to DNS server
$session = New-PSSession -ComputerName "dns-server" -Credential (Get-Credential)
Copy-Item -Path "C:\certificates\dns.pfx" -Destination "C:\Temp\" -ToSession $session

# Import via API (requires API token)
$headers = @{"Authorization" = "Bearer your-api-token"}
$body = @{
    "pfxCertificate" = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\certificates\dns.pfx"))
    "pfxPassword" = "secure-password"
}
Invoke-RestMethod -Uri "http://dns-server:5380/api/admin/certificates/import" -Method POST -Headers $headers -Body ($body | ConvertTo-Json)
```

## DNS-over-HTTPS Configuration

### Enable DoH

1. **Settings → DNS Settings → Optional Protocols**
2. **Enable**: DNS-over-HTTPS (DoH)
3. **Certificate**: Select imported certificate
4. **Port**: 443 (default) or custom
5. **URL Path**: `/dns-query` (default)

### Test DoH

```bash
# Test with curl
curl -H "Accept: application/dns-json" "https://dns.example.com/dns-query?name=google.com&type=A"

# Test with DoH client
echo "google.com" | doh-client -u "https://dns.example.com/dns-query"
```

```powershell
# PowerShell test
$headers = @{"Accept" = "application/dns-json"}
Invoke-RestMethod -Uri "https://dns.example.com/dns-query?name=google.com&type=A" -Headers $headers
```

## DNS-over-TLS Configuration

### Enable DoT

1. **Settings → DNS Settings → Optional Protocols**
2. **Enable**: DNS-over-TLS (DoT)
3. **Certificate**: Select imported certificate
4. **Port**: 853 (default) or custom

### Test DoT

```bash
# Test with kdig (if available)
kdig @dns.example.com +tls-ca +tls-hostname=dns.example.com google.com

# Test with OpenSSL
echo -e "\x00\x1c\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01" | \
  openssl s_client -connect dns.example.com:853 -servername dns.example.com -quiet
```

## Certificate Automation

### Automatic Renewal (Let's Encrypt)

```bash
# Create renewal script
cat > /usr/local/bin/renew-dns-cert.sh << 'EOF'
#!/bin/bash

# Renew certificate
certbot renew --quiet

# Convert to PFX
if [ -f /etc/letsencrypt/live/dns.example.com/fullchain.pem ]; then
    openssl pkcs12 -export \
      -out /etc/letsencrypt/live/dns.example.com/dns.pfx \
      -inkey /etc/letsencrypt/live/dns.example.com/privkey.pem \
      -in /etc/letsencrypt/live/dns.example.com/fullchain.pem \
      -password pass:your-secure-password
    
    # Restart Technitium DNS Server
    systemctl restart technitium-dns
fi
EOF

# Make executable
chmod +x /usr/local/bin/renew-dns-cert.sh

# Add to crontab (daily check)
echo "0 2 * * * /usr/local/bin/renew-dns-cert.sh" | crontab -
```

### PowerShell Automation

```powershell
# Create scheduled task for certificate renewal
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\renew-certificates.ps1"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "2:00 AM"
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2)

Register-ScheduledTask -TaskName "DNS Certificate Renewal" -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest
```

## Certificate Monitoring

### Expiration Monitoring Script

```powershell
# Monitor certificate expiration
param(
    [string]$CertificatePath = "C:\certificates\dns.pfx",
    [string]$Password = "secure-password",
    [int]$WarningDays = 30
)

try {
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath, $Password)
    $daysUntilExpiry = ($cert.NotAfter - (Get-Date)).Days
    
    if ($daysUntilExpiry -le $WarningDays) {
        Write-Warning "Certificate expires in $daysUntilExpiry days ($($cert.NotAfter))"
        # Send email notification, etc.
    }
    else {
        Write-Host "Certificate is valid for $daysUntilExpiry more days"
    }
}
catch {
    Write-Error "Failed to check certificate: $($_.Exception.Message)"
}
```

### API Monitoring

```powershell
# Check certificate via API
$response = Invoke-RestMethod -Uri "http://dns-server:5380/api/admin/certificates/list" -Headers $headers
$certificates = $response.certificates

foreach ($cert in $certificates) {
    $expiryDate = [DateTime]::Parse($cert.notAfter)
    $daysLeft = ($expiryDate - (Get-Date)).Days
    
    Write-Host "Certificate: $($cert.subject) - Expires in $daysLeft days"
}
```

## Troubleshooting

### Common Certificate Issues

#### 1. Certificate Not Trusted
```bash
# Add root CA to trust store (Linux)
sudo cp ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

```powershell
# Add root CA to trust store (Windows)
Import-Certificate -FilePath "C:\certificates\ca.crt" -CertStoreLocation "Cert:\LocalMachine\Root"
```

#### 2. Subject Alternative Name Issues
```bash
# Check certificate SAN
openssl x509 -in dns.crt -text -noout | grep -A 1 "Subject Alternative Name"
```

#### 3. Private Key Issues
```bash
# Verify private key matches certificate
openssl x509 -noout -modulus -in dns.crt | openssl md5
openssl rsa -noout -modulus -in dns.key | openssl md5
# Hashes should match
```

#### 4. PFX Password Issues
```powershell
# Test PFX file and password
try {
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("dns.pfx", "password")
    Write-Host "Certificate loaded successfully: $($cert.Subject)"
}
catch {
    Write-Error "Failed to load certificate: $($_.Exception.Message)"
}
```

### Certificate Validation Tools

```bash
# Validate certificate chain
openssl verify -CAfile ca.crt dns.crt

# Check certificate details
openssl x509 -in dns.crt -text -noout

# Test TLS connection
openssl s_client -connect dns.example.com:853 -servername dns.example.com
```

### Debugging DoH/DoT

```bash
# Check if certificates are properly configured
echo "Q" | openssl s_client -connect dns.example.com:853 2>&1 | grep -E "(Verify|Certificate chain)"

# Test DoH endpoint
curl -v "https://dns.example.com/dns-query?name=test.com&type=A"
```

## Security Best Practices

### Certificate Security

1. **Strong Passwords**: Use complex passwords for PFX files
2. **Secure Storage**: Protect private keys with proper file permissions
3. **Regular Rotation**: Rotate certificates before expiration
4. **Monitoring**: Implement automated expiration monitoring
5. **Backup**: Maintain secure backups of certificates and keys

### Access Control

```bash
# Set proper file permissions (Linux)
chmod 600 /etc/ssl/private/dns.key
chown root:root /etc/ssl/private/dns.key

# Windows - Set file ACLs
icacls "C:\certificates\dns.pfx" /inheritance:d /grant:r "Administrators:F" "SYSTEM:F" /remove "Users"
```

### Certificate Policies

- **Use strong key sizes** (2048-bit RSA minimum, 4096-bit preferred)
- **Enable OCSP stapling** for certificate status checking
- **Implement certificate transparency** monitoring
- **Use HSTS headers** for web console HTTPS
- **Regular security audits** of certificate infrastructure
