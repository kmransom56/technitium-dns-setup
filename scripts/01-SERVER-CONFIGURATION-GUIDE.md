# Technitium DNS Server Configuration Guide

## Overview

This guide covers the complete configuration of Technitium DNS Server with secure certificate management, including DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) setup.

## Prerequisites

- Windows Server or Linux server
- Static IP address
- Valid TLS certificates (PFX format)
- Network access to certificate authority
- Administrative privileges

## Installation Methods

### Method 1: Windows Installer

```powershell
# Download and install
Invoke-WebRequest -Uri "https://download.technitium.com/dns/DnsServerSetup.zip" -OutFile "DnsServerSetup.zip"
Expand-Archive -Path "DnsServerSetup.zip" -DestinationPath "C:\Temp\TechnitiumDNS"
Start-Process -FilePath "C:\Temp\TechnitiumDNS\DnsServerSetup.exe" -Wait
```

### Method 2: Portable Version

```powershell
# Download portable version
Invoke-WebRequest -Uri "https://download.technitium.com/dns/DnsServerPortable.tar.gz" -OutFile "DnsServerPortable.tar.gz"
# Extract to desired location
# Run DnsServerApp.exe
```

### Method 3: Docker Container

```bash
docker run -d \
  --name technitium-dns \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 5380:5380 \
  -p 853:853 \
  -p 443:443 \
  -v technitium-dns-data:/etc/dns \
  --restart unless-stopped \
  technitium/dns-server:latest
```

## Initial Configuration

### 1. Web Console Access

- URL: `http://localhost:5380`
- Default Username: `admin`
- Default Password: `admin`
- **Change password immediately after first login!**

### 2. Basic DNS Settings

1. Navigate to **Settings → DNS Settings**
2. Configure **Forwarders**:
   - Cloudflare: `1.1.1.1`, `1.0.0.1`
   - Google: `8.8.8.8`, `8.8.4.4`
   - Quad9: `9.9.9.9`, `149.112.112.112`

### 3. Enable Recursive Resolution

- Settings → DNS Settings → **Recursion**
- Enable "Allow Recursion"
- Set "Recursion Denial" for unauthorized clients

## Certificate Installation

### 1. Prepare PFX Certificates

```powershell
# Verify certificate files exist
Get-ChildItem -Path "C:\Path\To\Certificates\*.pfx"

# Test certificate validity
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("path\to\cert.pfx", "password")
Write-Host "Certificate Subject: $($cert.Subject)"
Write-Host "Has Private Key: $($cert.HasPrivateKey)"
Write-Host "Valid Until: $($cert.NotAfter)"
```

### 2. Import Certificates via Web Console

1. Navigate to **Settings → Certificates**
2. Click **Import Certificate**
3. Select PFX file and enter password
4. Verify certificate appears in list

## DNS-over-HTTPS (DoH) Configuration

### 1. Enable DoH Protocol

1. Settings → DNS Settings → **Optional Protocols**
2. Enable "DNS-over-HTTPS (DoH)"
3. Select imported certificate
4. Set HTTPS port (default: 443)

### 2. Configure DoH URL

- DoH URL format: `https://your-dns-server/dns-query`
- Test URL: `https://your-dns-server:443/dns-query`

### 3. Test DoH Functionality

```powershell
# Test DoH query
$headers = @{"Content-Type"="application/dns-message"}
$dnsQuery = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("google.com"))
Invoke-RestMethod -Uri "https://your-dns-server/dns-query?dns=$dnsQuery" -Headers $headers
```

## DNS-over-TLS (DoT) Configuration

### 1. Enable DoT Protocol

1. Settings → DNS Settings → **Optional Protocols**
2. Enable "DNS-over-TLS (DoT)"
3. Select same certificate as DoH
4. Set TLS port (default: 853)

### 2. Test DoT Functionality

```bash
# Using kdig (if available)
kdig @your-dns-server +tls google.com

# Using openssl
echo -e "\x00\x1c\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01" | openssl s_client -connect your-dns-server:853 -quiet
```

## Ad Blocking Configuration

### 1. Configure Block Lists

1. Navigate to **Settings → Blocking**
2. Add popular block list URLs:
   - **Steven Black's Hosts**: `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts`
   - **AdGuard DNS Filter**: `https://adguardteam.github.io/AdguardFilters/DnsFilter/filter.txt`
   - **EasyList**: `https://easylist.to/easylist/easylist.txt`

### 2. Block List Settings

- Update interval: 24 hours (recommended)
- Enable automatic updates
- Configure allow lists for false positives

## Zone Management

### 1. Create Local Zones

```powershell
# Example: Create internal domain zone
# Via API or web console
# Zone: internal.company.com
# Type: Primary
```

### 2. Add DNS Records

- **A Records**: Point hostnames to IP addresses
- **CNAME Records**: Create aliases
- **MX Records**: Mail server configuration
- **TXT Records**: Verification and configuration

## Security Hardening

### 1. Access Control

1. **Administration → Users**
2. Create individual user accounts
3. Disable default admin account
4. Use strong passwords
5. Enable two-factor authentication (if available)

### 2. Network Security

```powershell
# Windows Firewall rules
New-NetFirewallRule -DisplayName "DNS UDP" -Direction Inbound -Protocol UDP -LocalPort 53
New-NetFirewallRule -DisplayName "DNS TCP" -Direction Inbound -Protocol TCP -LocalPort 53
New-NetFirewallRule -DisplayName "DNS over TLS" -Direction Inbound -Protocol TCP -LocalPort 853
New-NetFirewallRule -DisplayName "DNS over HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443
New-NetFirewallRule -DisplayName "DNS Web Console" -Direction Inbound -Protocol TCP -LocalPort 5380
```

### 3. DNSSEC Configuration

1. Settings → DNS Settings → **DNSSEC**
2. Enable DNSSEC validation
3. Configure trust anchors (auto-download recommended)
4. Test DNSSEC functionality

## Performance Optimization

### 1. Cache Configuration

- **Cache Size**: Increase based on available memory
- **Cache TTL**: Balance between performance and freshness
- **Prefetching**: Enable for popular domains

### 2. Forwarder Optimization

- Use multiple forwarders for redundancy
- Choose geographically close forwarders
- Enable concurrent queries
- Configure fallback options

## Monitoring and Logging

### 1. Enable Logging

1. **Administration → Settings → Logging**
2. Set appropriate log level (Info for production)
3. Configure log retention period
4. Enable query logging if needed

### 2. Monitor Performance

- Dashboard shows real-time statistics
- Monitor cache hit ratio
- Track query response times
- Review blocked queries

## Backup and Recovery

### 1. Configuration Backup

```powershell
# Backup configuration
Copy-Item -Path "C:\ProgramData\Technitium\DnsServer\config\dns.config" -Destination "C:\Backups\dns.config.bak"

# Backup zones
Copy-Item -Path "C:\ProgramData\Technitium\DnsServer\zones\*" -Destination "C:\Backups\zones\" -Recurse
```

### 2. Automated Backups

```powershell
# Create scheduled task for daily backups
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\backup-dns.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At "2:00 AM"
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "DNS Server Backup" -Description "Daily backup of DNS server configuration"
```

## Troubleshooting

### Common Issues

#### 1. Certificate Import Failures
- Verify PFX format and password
- Check certificate expiration
- Ensure private key is included
- Validate certificate chain

#### 2. DoH/DoT Not Working
- Verify certificate matches server FQDN
- Check firewall rules
- Ensure proper DNS resolution for server name
- Test certificate validity

#### 3. Performance Issues
- Monitor system resources
- Adjust cache settings
- Review forwarder configuration
- Check network connectivity

### Debug Commands

```powershell
# Test DNS resolution
nslookup google.com your-dns-server

# Test DoH
curl -H "Accept: application/dns-json" "https://your-dns-server/dns-query?name=google.com&type=A"

# Check certificate
openssl s_client -connect your-dns-server:853 -servername your-dns-server
```

## Advanced Configuration

### 1. Custom DNS Apps

- Develop custom DNS applications
- Handle specific DNS queries with business logic
- Implement geolocation-based responses
- Create custom filtering rules

### 2. Split Horizon DNS

- Different responses for internal vs external clients
- Network-based view configuration
- Client subnet identification

### 3. API Integration

```powershell
# Example API usage
$headers = @{"Authorization" = "Bearer your-api-token"}
$response = Invoke-RestMethod -Uri "http://your-dns-server:5380/api/zones/list" -Headers $headers
```

## Maintenance Tasks

### Daily Tasks
- Review dashboard for anomalies
- Check log files for errors
- Verify certificate expiration dates

### Weekly Tasks
- Review block list effectiveness
- Update DNS forwarders if needed
- Analyze query statistics

### Monthly Tasks
- Update Technitium DNS Server
- Review and rotate API tokens
- Test backup and recovery procedures
- Performance optimization review

## Support Resources

- **Official Documentation**: https://go.technitium.com/?id=25
- **GitHub Issues**: https://github.com/TechnitiumSoftware/DnsServer/issues
- **Reddit Community**: https://www.reddit.com/r/technitium/
- **Email Support**: support@technitium.com
