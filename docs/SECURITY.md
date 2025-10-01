# Security Configuration for Technitium DNS Server

## Security Overview

Technitium DNS Server provides multiple layers of security:
- **Encrypted DNS protocols** (DoH, DoT, DoQ)
- **DNSSEC validation** and signing
- **Access control** and authentication
- **Network security** and firewall integration
- **Audit logging** and monitoring

## Initial Security Setup

### 1. Change Default Credentials

```powershell
# Via Web Console:
# 1. Login with admin/admin
# 2. Administration → Users → Edit admin user
# 3. Set strong password
# 4. Enable two-factor authentication (if available)

# Via API:
$headers = @{"Authorization" = "Bearer admin-token"}
$body = @{
    "password" = "new-secure-password"
    "newPassword" = "even-more-secure-password"
}
Invoke-RestMethod -Uri "http://dns-server:5380/api/admin/changePassword" -Method POST -Headers $headers -Body ($body | ConvertTo-Json)
```

### 2. Disable Default Admin Account

1. **Create new admin user** with different name
2. **Assign administrator role** to new user
3. **Test new account** functionality
4. **Disable default admin account**

### 3. Enable HTTPS for Web Console

```powershell
# Install TLS certificate (see CERTIFICATES.md)
# Configure HTTPS in Settings → Web Service
# Redirect HTTP to HTTPS
# Enable HSTS headers
```

## User Management and Access Control

### Role-Based Access Control

#### Built-in Roles:
- **Administrator**: Full system access
- **DNS Administrator**: DNS zone management
- **DHCP Administrator**: DHCP configuration
- **User**: Limited read-only access

#### Create Custom Users:

```json
{
  "username": "dns-operator",
  "password": "secure-password",
  "displayName": "DNS Operator",
  "memberOfGroups": ["DNS Administrators"],
  "disabled": false
}
```

### API Token Security

```powershell
# Generate API token with limited scope
$tokenRequest = @{
    "tokenName" = "monitoring-token"
    "expiryDays" = 90
    "permissions" = @("ViewStats", "ViewLogs")
}

$response = Invoke-RestMethod -Uri "http://dns-server:5380/api/admin/tokens/create" -Method POST -Headers $headers -Body ($tokenRequest | ConvertTo-Json)
$apiToken = $response.token

# Store securely and rotate regularly
```

## Network Security

### Firewall Configuration

#### Windows Firewall
```powershell
# Allow DNS services
New-NetFirewallRule -DisplayName "DNS UDP" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow
New-NetFirewallRule -DisplayName "DNS TCP" -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow

# Secure protocols
New-NetFirewallRule -DisplayName "DNS-over-TLS" -Direction Inbound -Protocol TCP -LocalPort 853 -Action Allow
New-NetFirewallRule -DisplayName "DNS-over-HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow

# Management (restrict to admin networks)
New-NetFirewallRule -DisplayName "DNS Console" -Direction Inbound -Protocol TCP -LocalPort 5380 -RemoteAddress "192.168.1.0/24" -Action Allow

# Block all other traffic to DNS server
New-NetFirewallRule -DisplayName "Block DNS Other" -Direction Inbound -Action Block -Enabled True
```

#### Linux iptables
```bash
# Allow DNS services
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT

# Secure DNS protocols
iptables -A INPUT -p tcp --dport 853 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Restrict management access
iptables -A INPUT -p tcp --dport 5380 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 5380 -j DROP

# Save rules
iptables-save > /etc/iptables/rules.v4
```

### Network Access Control

#### IP Address Restrictions
```json
{
  "webServiceLocalAddresses": ["192.168.1.100"],
  "webServiceHttpPort": 5380,
  "webServiceEnableHttps": true,
  "webServiceHttpsPort": 5443,
  "webServiceUseSelfSignedTlsCertificate": false
}
```

#### Client Access Control
```json
{
  "allowRecursion": true,
  "allowRecursionOnlyForPrivateNetworks": true,
  "recursionDeniedNetworks": ["0.0.0.0/0"],
  "recursionAllowedNetworks": [
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12"
  ]
}
```

## DNSSEC Configuration

### Enable DNSSEC Validation

1. **Settings → DNS Settings → DNSSEC**
2. **Enable DNSSEC validation**
3. **Configure trust anchors** (auto-update recommended)
4. **Set validation policy** (strict recommended)

### DNSSEC Signing (Authoritative Zones)

```powershell
# Enable DNSSEC for zone
$zoneConfig = @{
    "zone" = "example.com"
    "dnssecStatus" = "SignedWithNSEC3"
    "kskAlgorithm" = "RSASHA256"
    "zskAlgorithm" = "RSASHA256"
    "kskKeySize" = 2048
    "zskKeySize" = 1024
    "nsec3Iterations" = 10
    "nsec3SaltLength" = 8
}

Invoke-RestMethod -Uri "http://dns-server:5380/api/zones/dnssec/sign" -Method POST -Headers $headers -Body ($zoneConfig | ConvertTo-Json)
```

### DNSSEC Key Management

```bash
# Generate KSK (Key Signing Key)
dnssec-keygen -a RSASHA256 -b 2048 -f KSK example.com

# Generate ZSK (Zone Signing Key)  
dnssec-keygen -a RSASHA256 -b 1024 example.com

# Sign zone
dnssec-signzone -o example.com example.com.zone
```

## Logging and Monitoring

### Security Event Logging

```json
{
  "logQueries": true,
  "logQueriesIgnoreList": [
    "localhost",
    "*.local"
  ],
  "logLevel": "Info",
  "maxLogFileDays": 30,
  "maxLogFileSize": 104857600
}
```

### Failed Authentication Monitoring

```powershell
# Monitor failed login attempts
$logPath = "C:\ProgramData\Technitium\DnsServer\logs"
$failedLogins = Get-Content "$logPath\*.log" | Select-String "Authentication failed"

if ($failedLogins.Count -gt 10) {
    Write-Warning "Multiple failed login attempts detected!"
    # Send alert, block IPs, etc.
}
```

### Query Analysis

```powershell
# Analyze suspicious DNS queries
$suspiciousPatterns = @(
    ".*\.onion",
    ".*\.bit",
    "[0-9a-f]{16,}\..*",  # Possible DGA domains
    ".*tunnel.*",
    ".*\.tk$",
    ".*\.ml$"
)

$queryLog = Get-Content "C:\ProgramData\Technitium\DnsServer\logs\query.log"
foreach ($pattern in $suspiciousPatterns) {
    $matches = $queryLog | Select-String $pattern
    if ($matches) {
        Write-Warning "Suspicious queries detected: $pattern"
    }
}
```

## Threat Protection

### Malware Domain Blocking

```json
{
  "blockListUrls": [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://mirror1.malwaredomains.com/files/justdomains",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0",
    "https://threatfox.abuse.ch/downloads/hostfile/"
  ],
  "blockListUpdateIntervalHours": 24,
  "blockListMaxFileSizeBytes": 10485760
}
```

### DNS Rebinding Protection

```json
{
  "enableDnsRebindingProtection": true,
  "dnsRebindingProtectionExceptions": [
    "router.local",
    "*.lan",
    "192.168.0.0/16",
    "10.0.0.0/8"
  ]
}
```

### Rate Limiting

```json
{
  "recursionTimeout": 5000,
  "recursionRetries": 2,
  "clientTimeout": 4000,
  "maxStackCount": 16,
  "enableLogging": true
}
```

## Encrypted DNS Protocols

### DNS-over-HTTPS (DoH) Security

```json
{
  "enableDnsOverHttps": true,
  "dnsOverHttpsPort": 443,
  "dnsOverHttpsCertificate": "dns.example.com.pfx",
  "dnsOverHttpsEnableHttp2": true,
  "dnsOverHttpsEnableHttp3": true,
  "enableHttpsRedirection": true
}
```

### DNS-over-TLS (DoT) Security

```json
{
  "enableDnsOverTls": true,
  "dnsOverTlsPort": 853,
  "dnsOverTlsCertificate": "dns.example.com.pfx",
  "dnsOverTlsMinVersion": "TLS12",
  "dnsOverTlsCipherSuites": [
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
  ]
}
```

### DNS-over-QUIC (DoQ) Security

```json
{
  "enableDnsOverQuic": true,
  "dnsOverQuicPort": 853,
  "dnsOverQuicCertificate": "dns.example.com.pfx",
  "dnsOverQuicIdleTimeout": 30000
}
```

## Security Hardening

### System-Level Security

#### Windows
```powershell
# Run as service with limited privileges
New-LocalUser -Name "dns-service" -Password (ConvertTo-SecureString "password" -AsPlainText -Force) -Description "DNS Service Account"
Add-LocalGroupMember -Group "Log on as a service" -Member "dns-service"

# Set service to run as dns-service user
Set-Service "Technitium DNS Server" -StartupType Automatic
sc.exe config "Technitium DNS Server" obj= ".\dns-service" password= "password"
```

#### Linux
```bash
# Create dedicated user
sudo useradd -r -s /bin/false -c "DNS Service" dns-service

# Set file permissions
sudo chown -R dns-service:dns-service /opt/technitium-dns
sudo chmod 750 /opt/technitium-dns

# Configure service to run as dns-service
sudo systemctl edit technitium-dns
# Add:
# [Service]
# User=dns-service
# Group=dns-service
```

### File System Security

```bash
# Linux file permissions
chmod 600 /opt/technitium-dns/config/dns.config
chmod 600 /opt/technitium-dns/config/*.pfx
chown dns-service:dns-service /opt/technitium-dns/config/*
```

```powershell
# Windows file ACLs
$configPath = "C:\ProgramData\Technitium\DnsServer\config"
icacls $configPath /inheritance:d
icacls $configPath /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" "dns-service:(OI)(CI)R"
icacls $configPath /remove "Users" "Everyone"
```

## Security Monitoring

### Automated Security Checks

```powershell
# Security audit script
param(
    [string]$DNSServer = "localhost",
    [string]$LogPath = "C:\ProgramData\Technitium\DnsServer\logs"
)

$SecurityIssues = @()

# Check for default passwords
try {
    $response = Invoke-RestMethod -Uri "http://$DNSServer:5380/api/login" -Method POST -Body (@{username="admin"; password="admin"} | ConvertTo-Json)
    $SecurityIssues += "Default admin password still in use"
}
catch {
    Write-Host "✓ Default password has been changed"
}

# Check HTTPS configuration
try {
    $response = Invoke-WebRequest -Uri "https://$DNSServer:5380" -SkipCertificateCheck
    Write-Host "✓ HTTPS is configured"
}
catch {
    $SecurityIssues += "HTTPS not configured for web console"
}

# Check certificate expiration
$certFiles = Get-ChildItem "$LogPath\..\config\*.pfx"
foreach ($cert in $certFiles) {
    try {
        $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert.FullName)
        $daysLeft = ($x509.NotAfter - (Get-Date)).Days
        if ($daysLeft -lt 30) {
            $SecurityIssues += "Certificate $($cert.Name) expires in $daysLeft days"
        }
    }
    catch {
        $SecurityIssues += "Cannot validate certificate $($cert.Name)"
    }
}

# Report issues
if ($SecurityIssues.Count -gt 0) {
    Write-Warning "Security issues found:"
    $SecurityIssues | ForEach-Object { Write-Warning "  • $_" }
}
else {
    Write-Host "✓ No security issues detected" -ForegroundColor Green
}
```

### Intrusion Detection

```bash
#!/bin/bash
# Simple IDS for DNS server

LOG_FILE="/var/log/technitium/dns.log"
ALERT_EMAIL="admin@example.com"
THRESHOLD=100

# Monitor for excessive queries from single IP
awk '{print $1}' $LOG_FILE | sort | uniq -c | while read count ip; do
    if [ $count -gt $THRESHOLD ]; then
        echo "Alert: Excessive queries from $ip ($count queries)" | mail -s "DNS Security Alert" $ALERT_EMAIL
    fi
done

# Monitor for suspicious query patterns
grep -i "onion\|bit\|tunnel" $LOG_FILE | if [ $(wc -l) -gt 10 ]; then
    echo "Alert: Suspicious domain queries detected" | mail -s "DNS Security Alert" $ALERT_EMAIL
fi
```

## Backup and Recovery

### Configuration Backup

```powershell
# Automated backup script
$BackupPath = "C:\Backups\DNS\$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$ConfigPath = "C:\ProgramData\Technitium\DnsServer"

New-Item -ItemType Directory -Path $BackupPath -Force

# Backup configuration
Copy-Item "$ConfigPath\config\*" $BackupPath -Recurse

# Backup zones
Copy-Item "$ConfigPath\zones\*" $BackupPath -Recurse

# Backup logs (last 7 days)
$RecentLogs = Get-ChildItem "$ConfigPath\logs" | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }
$RecentLogs | Copy-Item -Destination $BackupPath

# Compress backup
Compress-Archive -Path $BackupPath -DestinationPath "$BackupPath.zip"
Remove-Item $BackupPath -Recurse -Force

Write-Host "Backup created: $BackupPath.zip"
```

### Disaster Recovery

```powershell
# Recovery script
param(
    [string]$BackupFile = "C:\Backups\DNS\backup.zip",
    [string]$RestorePath = "C:\ProgramData\Technitium\DnsServer"
)

# Stop DNS service
Stop-Service "Technitium DNS Server" -Force

# Extract backup
Expand-Archive -Path $BackupFile -DestinationPath "C:\Temp\restore" -Force

# Restore configuration
Copy-Item "C:\Temp\restore\*" $RestorePath -Recurse -Force

# Start DNS service
Start-Service "Technitium DNS Server"

# Verify service status
Get-Service "Technitium DNS Server"

Write-Host "Recovery completed from: $BackupFile"
```

## Compliance and Auditing

### Audit Logging

```json
{
  "enableAuditLog": true,
  "auditLogLevel": "Detailed",
  "auditLogRetentionDays": 365,
  "auditEvents": [
    "UserLogin",
    "UserLogout",
    "ConfigurationChange",
    "ZoneModification",
    "CertificateImport",
    "SecurityEvent"
  ]
}
```

### Compliance Reports

```powershell
# Generate compliance report
$Report = @{
    "GeneratedDate" = Get-Date
    "ServerInfo" = @{
        "Version" = "13.6"
        "DNSSEC" = $true
        "EncryptedDNS" = $true
        "AccessControl" = $true
    }
    "SecurityChecks" = @{
        "DefaultPasswordChanged" = $true
        "HTTPSEnabled" = $true
        "CertificateValid" = $true
        "FirewallConfigured" = $true
        "LoggingEnabled" = $true
    }
    "ThreatProtection" = @{
        "MalwareBlocking" = $true
        "DNSRebindingProtection" = $true
        "RateLimiting" = $true
        "QueryLogging" = $true
    }
}

$Report | ConvertTo-Json -Depth 3 | Out-File "compliance-report-$(Get-Date -Format 'yyyyMMdd').json"
```

## Security Best Practices Summary

### Critical Actions
1. ✅ **Change default passwords immediately**
2. ✅ **Enable HTTPS for web console**
3. ✅ **Install valid TLS certificates**
4. ✅ **Configure firewall rules**
5. ✅ **Enable DNSSEC validation**
6. ✅ **Set up encrypted DNS protocols**
7. ✅ **Configure malware blocking**
8. ✅ **Enable security logging**
9. ✅ **Implement backup procedures**
10. ✅ **Monitor security events**

### Ongoing Maintenance
- **Regular security audits**
- **Certificate renewal monitoring**
- **Log analysis and alerting**
- **Software updates and patches**
- **Access review and cleanup**
- **Backup testing and validation**

### Emergency Response
- **Incident response procedures**
- **Contact information for security team**
- **Rollback and recovery plans**
- **Communication templates**
- **Post-incident analysis process**
