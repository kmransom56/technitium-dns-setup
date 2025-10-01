# Quick Reference Guide

## Certificate Setup Complete ✅

Both required PFX certificates have been generated successfully:

- **dns.netintegrate.net_full_chain.pfx** - 6.05 KB (with private key)
- **dns2.netintegrate.net_full_chain.pfx** - 3.13 KB (with private key)

## Certificate Details

- **Format**: PKCS#12 (.pfx) 
- **Password**: netintegrate (dns.netintegrate.net)
- **Password**: [empty] (dns2.netintegrate.net)
- **Validity**: 365 days
- **Contains**: Certificate + Private Key + Full Chain

## Next Steps

1. **Copy certificates to DNS server** (192.168.0.252)
2. **Import via Technitium web interface**
3. **Configure DoH/DoT services**
4. **Test secure DNS functionality**

## Certificate Authority

- **CA Server**: 192.168.0.251
- **FastAPI Backend**: http://192.168.0.251:8000
- **Management GUI**: http://192.168.0.251:3000

## Essential Commands

```powershell
# Verify certificates
.\20-FINAL-VERIFICATION.ps1

# Generate new certificate
.\16-WORKING-CERT-GEN.ps1 -DomainName "dns.example.com"

# Test all services
.\02-TEST-ALL.ps1

# Troubleshoot issues
.\03-TROUBLESHOOT.ps1
```

## Certificate Locations

- **Local Path**: C:\Users\south\Documents\technitium-setup\certificates
- **Remote CA**: /opt/ca/deploy/
- **cert-manager**: /opt/cert-manager/