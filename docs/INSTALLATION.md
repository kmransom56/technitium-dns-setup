# Technitium DNS Server Installation Guide

## Quick Installation

### Windows

1. **Download Installer**
   ```powershell
   Invoke-WebRequest -Uri "https://download.technitium.com/dns/DnsServerSetup.zip" -OutFile "DnsServerSetup.zip"
   Expand-Archive -Path "DnsServerSetup.zip" -DestinationPath "C:\Temp\TechnitiumDNS"
   ```

2. **Run Installation**
   ```powershell
   Start-Process -FilePath "C:\Temp\TechnitiumDNS\DnsServerSetup.exe" -Wait
   ```

3. **Access Web Console**
   - Open browser: `http://localhost:5380`
   - Default login: `admin` / `admin`
   - **Change password immediately!**

### Linux (Ubuntu/Debian)

```bash
# Install .NET 8 Runtime
wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get update
sudo apt-get install -y dotnet-runtime-8.0

# Download and extract Technitium DNS
wget https://download.technitium.com/dns/DnsServerPortable.tar.gz
tar -xzf DnsServerPortable.tar.gz
cd DnsServerPortable

# Make executable and run
chmod +x DnsServerApp
./DnsServerApp
```

### Docker

```bash
# Pull official image
docker pull technitium/dns-server:latest

# Create data volume
docker volume create technitium-dns-data

# Run container
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

### Docker Compose

```yaml
version: '3.8'
services:
  technitium-dns:
    image: technitium/dns-server:latest
    container_name: technitium-dns
    ports:
      - "53:53/udp"
      - "53:53/tcp" 
      - "5380:5380"
      - "853:853"
      - "443:443"
    volumes:
      - technitium-dns-data:/etc/dns
    environment:
      - DNS_SERVER_DOMAIN=dns.example.com
      - DNS_SERVER_ADMIN_PASSWORD=secure-password
    restart: unless-stopped
    
volumes:
  technitium-dns-data:
```

## Advanced Installation

### Raspberry Pi

```bash
# Install .NET runtime for ARM
curl -sSL https://dot.net/v1/dotnet-install.sh | bash /dev/stdin --runtime dotnet --version 8.0.0
echo 'export PATH=$PATH:$HOME/.dotnet' >> ~/.bashrc
source ~/.bashrc

# Download Technitium DNS
wget https://download.technitium.com/dns/DnsServerPortable.tar.gz
tar -xzf DnsServerPortable.tar.gz

# Create systemd service
sudo tee /etc/systemd/system/technitium-dns.service > /dev/null <<EOF
[Unit]
Description=Technitium DNS Server
After=network.target

[Service]
Type=simple
User=dns
WorkingDirectory=/opt/technitium-dns
ExecStart=/home/pi/.dotnet/dotnet DnsServerApp.dll
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable technitium-dns
sudo systemctl start technitium-dns
```

### Windows Service Installation

```powershell
# Install as Windows Service
.\DnsServerApp.exe -install

# Start the service
Start-Service "Technitium DNS Server"

# Configure service to start automatically
Set-Service "Technitium DNS Server" -StartupType Automatic
```

## Initial Configuration

### 1. Web Console Access

- **URL**: `http://localhost:5380`
- **Default Credentials**: `admin` / `admin`
- **HTTPS**: Available after certificate installation

### 2. Change Default Password

1. Login with default credentials
2. Navigate to **Administration → Users**
3. Click **Edit** next to admin user
4. Set new secure password
5. **Save changes**

### 3. Basic DNS Settings

1. **Settings → DNS Settings**
2. **Forwarders** (recommended):
   ```
   Cloudflare: 1.1.1.1, 1.0.0.1
   Google: 8.8.8.8, 8.8.4.4
   Quad9: 9.9.9.9, 149.112.112.112
   ```
3. **Enable Recursion**: Allow for local network
4. **Cache Settings**: Increase cache size based on memory

### 4. Network Configuration

#### Windows Firewall
```powershell
# DNS (UDP/TCP)
New-NetFirewallRule -DisplayName "DNS UDP" -Direction Inbound -Protocol UDP -LocalPort 53
New-NetFirewallRule -DisplayName "DNS TCP" -Direction Inbound -Protocol TCP -LocalPort 53

# Web Console
New-NetFirewallRule -DisplayName "DNS Console" -Direction Inbound -Protocol TCP -LocalPort 5380

# DNS-over-TLS
New-NetFirewallRule -DisplayName "DNS-over-TLS" -Direction Inbound -Protocol TCP -LocalPort 853

# DNS-over-HTTPS  
New-NetFirewallRule -DisplayName "DNS-over-HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443
```

#### Linux UFW
```bash
# Allow DNS ports
sudo ufw allow 53/udp
sudo ufw allow 53/tcp
sudo ufw allow 5380/tcp
sudo ufw allow 853/tcp
sudo ufw allow 443/tcp
```

### 5. Client Configuration

#### Windows
```powershell
# Set DNS server for specific interface
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "192.168.1.100"

# Or via Control Panel → Network → Change Adapter Settings
```

#### Linux
```bash
# Edit resolv.conf
echo "nameserver 192.168.1.100" | sudo tee /etc/resolv.conf

# Or use systemd-resolved
sudo systemd-resolve --set-dns=192.168.1.100 --interface=eth0
```

#### Router/DHCP
- Configure DHCP server to provide DNS server IP
- Set primary DNS to Technitium server IP
- Set secondary DNS to public DNS (backup)

## Verification

### Test DNS Resolution
```powershell
# Basic test
nslookup google.com 192.168.1.100

# Test with dig (if available)
dig @192.168.1.100 google.com

# PowerShell test
Resolve-DnsName -Name "google.com" -Server "192.168.1.100"
```

### Test Web Console
```powershell
# Test web interface
Invoke-WebRequest -Uri "http://192.168.1.100:5380" -UseBasicParsing
```

### Monitor Logs
- **Windows**: `C:\ProgramData\Technitium\DnsServer\logs\`
- **Linux**: `./logs/` in installation directory
- **Docker**: `docker logs technitium-dns`

## Troubleshooting

### Common Issues

#### Port 53 Already in Use
```bash
# Linux - Check what's using port 53
sudo netstat -tulpn | grep :53

# Stop conflicting services
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
```

#### Permission Denied (Linux)
```bash
# Allow binding to privileged ports
sudo setcap 'cap_net_bind_service=+ep' ./DnsServerApp

# Or run as root (not recommended for production)
sudo ./DnsServerApp
```

#### Service Won't Start
```powershell
# Windows - Check service status
Get-Service "Technitium DNS Server"

# View service logs
Get-EventLog -LogName Application -Source "Technitium DNS Server" -Newest 10
```

#### Can't Access Web Console
1. Verify service is running
2. Check firewall rules
3. Try `http://127.0.0.1:5380`
4. Check if port 5380 is available

### Debug Mode

1. **Stop the service**
2. **Run manually with debug flags**:
   ```bash
   ./DnsServerApp -debug
   ```
3. **Check console output** for errors
4. **Review log files** for detailed information

### Performance Optimization

#### System Requirements
- **Minimum**: 512MB RAM, 1 CPU core
- **Recommended**: 2GB RAM, 2 CPU cores
- **High Traffic**: 4GB+ RAM, 4+ CPU cores

#### Configuration Tuning
```json
{
  "cacheMaximumEntries": 100000,
  "cachePrefetchEligibility": 2,
  "cachePreferredValidityDurationHours": 24,
  "recursionTimeout": 5000,
  "recursionRetries": 3
}
```

## Next Steps

1. **[Certificate Setup](CERTIFICATES.md)** - Configure TLS certificates
2. **[Security Configuration](SECURITY.md)** - Harden your installation
3. **[Ad Blocking Setup](BLOCKING.md)** - Configure content filtering
4. **[Monitoring Setup](MONITORING.md)** - Set up logging and alerts
