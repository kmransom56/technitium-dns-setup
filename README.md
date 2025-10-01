# Technitium DNS Server Complete Setup Guide

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Technitium DNS](https://img.shields.io/badge/Technitium_DNS-v13.6-blue.svg)](https://technitium.com/dns/)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue.svg)](https://docs.microsoft.com/en-us/powershell/)

A comprehensive setup guide and automation toolkit for **Technitium DNS Server** with secure certificate management, DNS-over-HTTPS (DoH), and DNS-over-TLS (DoT) configuration.

## 🚀 Quick Start

This repository provides complete automation for:
- **Certificate Authority Setup** with cert-manager
- **Secure Certificate Generation** for DNS services  
- **Technitium DNS Server Configuration** with TLS/HTTPS
- **PowerShell Automation Scripts** for the entire process
- **Comprehensive Documentation** from official sources

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation Guide](#installation-guide)
- [Certificate Management](#certificate-management)
- [DNS Server Configuration](#dns-server-configuration)
- [Security Setup](#security-setup)
- [Troubleshooting](#troubleshooting)
- [Scripts Reference](#scripts-reference)
- [Official Resources](#official-resources)

## 🎯 Overview

**Technitium DNS Server** is an open source authoritative and recursive DNS server that provides:

- **Privacy & Security**: Self-host DNS with encrypted protocols (DoH/DoT/DoQ)
- **Ad Blocking**: Network-wide ad and malware blocking at DNS level
- **High Performance**: Millions of requests per minute capability
- **Cross Platform**: Windows, Linux, macOS, Raspberry Pi, Docker
- **Zero Configuration**: Works out-of-the-box with minimal setup
- **Web Console**: User-friendly browser-based management interface

### Why Self-Host DNS?

- **Enhanced Privacy**: Your ISP cannot see or control your DNS queries
- **Network Control**: Block ads, malware, and unwanted content network-wide  
- **Performance**: Local caching improves website loading speeds
- **Security**: Encrypted DNS prevents man-in-the-middle attacks
- **Insights**: DNS logs provide network visibility and analytics

## ✨ Features

### Technitium DNS Server Core Features

- ✅ **Authoritative & Recursive DNS** - Full DNS server capabilities
- ✅ **Encrypted DNS Protocols** - DoH, DoT, DoQ support
- ✅ **Ad & Malware Blocking** - Configurable block lists
- ✅ **DNSSEC Validation** - RSA, ECDSA, EdDSA algorithms
- ✅ **Zone Management** - Primary, Secondary, Stub, Conditional Forwarder
- ✅ **Dynamic DNS Updates** - RFC 2136 compliant
- ✅ **Built-in DHCP Server** - Complete network service solution
- ✅ **API Access** - Full HTTP API for automation
- ✅ **Multi-User Support** - Role-based access control
- ✅ **Docker Support** - Container deployment ready

### This Repository Features

- 🔧 **Complete Automation** - PowerShell scripts for entire setup
- 🔐 **Certificate Authority** - Integrated cert-manager system
- 📜 **Certificate Generation** - Automated TLS certificate creation
- 🛡️ **Security Hardening** - Best practices implementation
- 📚 **Comprehensive Docs** - Step-by-step guides and references
- 🔍 **Troubleshooting** - Common issues and solutions
- ⚡ **Quick Reference** - Essential commands and configurations

## 📋 Prerequisites

### System Requirements

- **Operating System**: Windows 10/11, Linux, macOS, or Raspberry Pi OS
- **PowerShell**: Version 7.0+ (for automation scripts)
- **.NET Runtime**: Version 8.0+ (for Technitium DNS Server)
- **Network Access**: Internet connection for initial setup
- **Ports**: 53 (DNS), 5380 (Web Console), 853 (DoT), 443 (DoH)

### Required Modules & Tools

```powershell
# PowerShell modules
Install-Module -Name Posh-SSH -Force
Install-Module -Name Microsoft.PowerShell.SecretManagement -Force

# Optional but recommended
Install-Module -Name PSYaml -Force  # For configuration management
```

### Network Configuration

- **Static IP Address** recommended for DNS server
- **Firewall Rules** for DNS ports (53/UDP, 53/TCP)
- **Certificate Authority** accessible (port 8000/3000)
- **Administrative Access** to target DNS server

## 🚀 Installation Guide

### Method 1: Automated PowerShell Setup

```powershell
# Clone this repository
git clone https://github.com/kmransom56/technitium-dns-setup.git
cd technitium-dns-setup

# Run the complete setup
.\scripts\00-COMPLETE-SETUP.ps1 -DNSServer "192.168.1.100" -CAServer "192.168.1.101"
```

### Method 2: Manual Installation

1. **Download Technitium DNS Server**
   ```powershell
   # Windows - Download installer
   Invoke-WebRequest -Uri "https://download.technitium.com/dns/DnsServerSetup.zip" -OutFile "DnsServerSetup.zip"
   
   # Or portable version
   Invoke-WebRequest -Uri "https://download.technitium.com/dns/DnsServerPortable.tar.gz" -OutFile "DnsServerPortable.tar.gz"
   ```

2. **Install and Configure**
   ```powershell
   # Extract and install
   Expand-Archive -Path "DnsServerSetup.zip" -DestinationPath "C:\Temp\TechnitiumDNS"
   
   # Run installer (Windows)
   Start-Process -FilePath "C:\Temp\TechnitiumDNS\DnsServerSetup.exe" -Wait
   ```

3. **Access Web Console**
   - Open browser to `http://localhost:5380`
   - Default credentials: `admin` / `admin` 
   - **Change password immediately!**

### Method 3: Docker Deployment

```bash
# Pull official image
docker pull technitium/dns-server:latest

# Run with persistent storage
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

## 🔐 Certificate Management

### Certificate Authority Setup

Our setup includes an integrated certificate authority using **cert-manager**:

```powershell
# Deploy certificate authority
.\scripts\01-DEPLOY-CA.ps1 -CAServer "192.168.1.101"

# Verify CA services
.\scripts\02-VERIFY-CA.ps1 -CAServer "192.168.1.101"
```

### Certificate Generation

```powershell
# Generate DNS server certificates
.\scripts\03-GENERATE-CERTIFICATES.ps1 -Domain "dns.example.com"

# Create PFX files for Technitium
.\scripts\04-CREATE-PFX.ps1 -Domain "dns.example.com" -Password "your-secure-password"
```

### Certificate Deployment

```powershell
# Copy certificates to DNS server
.\scripts\05-DEPLOY-CERTIFICATES.ps1 -DNSServer "192.168.1.100" -CertificatePath ".\certificates"
```

## ⚙️ DNS Server Configuration

### Basic Configuration

1. **Access Web Console**
   ```
   URL: https://your-dns-server:5380
   Username: admin
   Password: [your-password]
   ```

2. **Configure Forwarders** (Settings → DNS Settings → Forwarders)
   ```
   Cloudflare DoH: https://1.1.1.1/dns-query
   Google DoH: https://8.8.8.8/dns-query
   Quad9 DoH: https://9.9.9.9/dns-query
   ```

3. **Enable DNS-over-HTTPS**
   - Go to Settings → DNS Settings → Optional Protocols
   - Enable "DNS-over-HTTPS"
   - Import your PFX certificate
   - Set certificate password

4. **Enable DNS-over-TLS**
   - Enable "DNS-over-TLS" in same section
   - Use the same certificate as DoH

### Ad Blocking Configuration

```powershell
# Configure popular block lists
.\scripts\06-CONFIGURE-BLOCKING.ps1 -DNSServer "192.168.1.100"
```

Popular block lists included:
- **Steven Black's Hosts**: Comprehensive ad/malware blocking
- **AdGuard DNS Filter**: Advanced ad blocking
- **EasyList**: Web advertisement blocking
- **Malware Domain List**: Known malicious domains

### Zone Configuration

```powershell
# Create local zones
.\scripts\07-CONFIGURE-ZONES.ps1 -DNSServer "192.168.1.100" -Domain "local.example.com"
```

## 🛡️ Security Setup

### TLS/HTTPS Configuration

1. **Certificate Requirements**
   - Valid TLS certificate for your DNS server FQDN
   - Certificate must include Subject Alternative Names (SAN)
   - Private key must be included in PFX format
   - Recommended: Use Let's Encrypt or internal CA

2. **Security Best Practices**
   ```powershell
   # Harden DNS server security
   .\scripts\08-SECURITY-HARDENING.ps1 -DNSServer "192.168.1.100"
   ```

3. **Firewall Configuration**
   ```powershell
   # Configure Windows Firewall rules
   .\scripts\09-CONFIGURE-FIREWALL.ps1
   ```

### DNSSEC Configuration

Enable DNSSEC validation for enhanced security:

1. **Enable DNSSEC** (Settings → DNS Settings → DNSSEC)
2. **Configure Trust Anchors** (automatic download recommended)
3. **Verify DNSSEC Status** using built-in tools

### Access Control

1. **User Management** (Administration → Users)
   - Create individual user accounts
   - Assign appropriate permissions
   - Disable default admin account after setup

2. **API Token Security**
   - Generate non-expiring tokens for automation
   - Rotate tokens regularly
   - Use minimum required permissions

## 🔧 Scripts Reference

### Core Setup Scripts

| Script | Purpose | Usage |
|--------|---------|-------|
| `00-COMPLETE-SETUP.ps1` | Full automated setup | `.\00-COMPLETE-SETUP.ps1 -DNSServer "IP"` |
| `01-SERVER-CONFIGURATION.ps1` | Basic server config | `.\01-SERVER-CONFIGURATION.ps1` |
| `02-TEST-ALL.ps1` | Comprehensive testing | `.\02-TEST-ALL.ps1` |
| `03-TROUBLESHOOT.ps1` | Diagnostic tools | `.\03-TROUBLESHOOT.ps1` |

### Certificate Management Scripts

| Script | Purpose | Usage |
|--------|---------|-------|
| `04-CERTIFICATE-HELPER.ps1` | Certificate utilities | `.\04-CERTIFICATE-HELPER.ps1 -Action "Generate"` |
| `05-MIGRATE-CERTIFICATES.ps1` | Certificate migration | `.\05-MIGRATE-CERTIFICATES.ps1 -Source "path"` |
| `06-RETRIEVE-CERTIFICATES.ps1` | Remote cert retrieval | `.\06-RETRIEVE-CERTIFICATES.ps1 -Server "IP"` |

### Advanced Configuration Scripts

| Script | Purpose | Usage |
|--------|---------|-------|
| `13-CERT-MANAGER-CLIENT.ps1` | Cert-manager integration | `.\13-CERT-MANAGER-CLIENT.ps1` |
| `16-WORKING-CERT-GEN.ps1` | Certificate generation | `.\16-WORKING-CERT-GEN.ps1 -Domain "dns.example.com"` |
| `20-FINAL-VERIFICATION.ps1` | Setup verification | `.\20-FINAL-VERIFICATION.ps1` |

## 🔍 Troubleshooting

### Common Issues

#### 1. Certificate Import Failures

```powershell
# Verify certificate format and password
.\scripts\diagnose-certificate.ps1 -CertPath "path\to\cert.pfx" -Password "password"

# Common solutions:
# - Ensure PFX contains both certificate and private key
# - Verify password is correct
# - Check certificate expiration date
# - Validate certificate chain
```

#### 2. DoH/DoT Not Working

```powershell
# Test encrypted DNS protocols
.\scripts\test-encrypted-dns.ps1 -Server "your-dns-server"

# Common solutions:
# - Verify certificate is valid for server FQDN
# - Check firewall allows ports 853 (DoT) and 443 (DoH)  
# - Ensure certificate includes proper Subject Alternative Names
# - Verify DNS server has correct time/date
```

#### 3. Performance Issues

```powershell
# DNS server performance analysis
.\scripts\analyze-performance.ps1 -Server "your-dns-server"

# Optimization tips:
# - Increase cache size in settings
# - Configure appropriate forwarders
# - Enable prefetching for popular domains
# - Monitor system resources (CPU/Memory)
```

#### 4. Block List Issues

```powershell
# Diagnose block list problems
.\scripts\test-blocking.ps1 -Domain "ads.example.com"

# Common solutions:
# - Verify block lists are downloading successfully
# - Check block list update intervals
# - Test with known blocked domains
# - Review block list format compatibility
```

### Debug Mode

Enable verbose logging for troubleshooting:

1. **Web Console**: Administration → Settings → Logging
2. **Log Level**: Set to "Debug" 
3. **Log Location**: Check `C:\ProgramData\Technitium\DnsServer\logs\`

### Support Resources

- **Official Documentation**: [Technitium Help Topics](https://go.technitium.com/?id=25)
- **GitHub Issues**: [TechnitiumSoftware/DnsServer](https://github.com/TechnitiumSoftware/DnsServer/issues)
- **Reddit Community**: [r/technitium](https://www.reddit.com/r/technitium/)
- **Email Support**: [support@technitium.com](mailto:support@technitium.com)

## 📚 Official Resources

### Primary Documentation

- **Official Website**: [technitium.com/dns](https://technitium.com/dns/)
- **GitHub Repository**: [TechnitiumSoftware/DnsServer](https://github.com/TechnitiumSoftware/DnsServer)
- **API Documentation**: [HTTP API Docs](https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md)
- **Docker Hub**: [technitium/dns-server](https://hub.docker.com/r/technitium/dns-server)

### Blog Posts & Tutorials

- [How to Host Your Own DNS-over-HTTPS and DNS-over-TLS Services](https://blog.technitium.com/2020/07/how-to-host-your-own-dns-over-https-and.html)
- [Blocking Internet Ads Using DNS Sinkhole](https://blog.technitium.com/2018/10/blocking-internet-ads-using-dns-sinkhole.html)
- [Configuring DNS Server for Privacy & Security](https://blog.technitium.com/2018/06/configuring-dns-server-for-privacy.html)
- [Running Technitium DNS Server on Ubuntu Linux](https://blog.technitium.com/2017/11/running-dns-server-on-ubuntu-linux.html)

### Community & Support

- **Patreon**: [Support Development](https://www.patreon.com/technitium)
- **Reddit**: [r/technitium Community](https://www.reddit.com/r/technitium/)
- **Mastodon**: [@technitium](https://mastodon.social/@technitium)

## 🤝 Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### How to Contribute

1. **Fork** this repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Areas for Contribution

- Additional PowerShell automation scripts
- Docker Compose configurations  
- Linux/macOS installation scripts
- Documentation improvements
- Bug fixes and optimizations
- Testing and validation scripts

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Third-Party Licenses

- **Technitium DNS Server**: GPL-3.0 License
- **cert-manager**: Apache 2.0 License
- **PowerShell Modules**: Various (see individual modules)

## 🙏 Acknowledgments

- **Technitium Software** for creating excellent DNS server software
- **cert-manager community** for certificate automation tools  
- **PowerShell community** for automation frameworks
- **Contributors** to this repository and related projects

## 📞 Support

For support with this setup guide:

- **Issues**: [GitHub Issues](https://github.com/kmransom56/technitium-dns-setup/issues)
- **Discussions**: [GitHub Discussions](https://github.com/kmransom56/technitium-dns-setup/discussions)

For Technitium DNS Server support:

- **Official Support**: [support@technitium.com](mailto:support@technitium.com)
- **Official Issues**: [Technitium GitHub](https://github.com/TechnitiumSoftware/DnsServer/issues)

---

**Made with ❤️ for the DNS privacy and security community**

⭐ **Star this repo** if it helped you set up secure DNS services!