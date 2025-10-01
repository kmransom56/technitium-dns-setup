#!/bin/bash
# Technitium DNS Server Docker Setup Script
# Automated deployment with certificates and monitoring

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DOCKER_DIR="$PROJECT_DIR/docker"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check if running as root (for privileged ports)
    if [[ $EUID -ne 0 ]] && [[ "$1" != "--no-root-check" ]]; then
        log_warning "Running without root privileges. DNS may not bind to port 53."
        log_info "To run with root privileges: sudo $0"
        log_info "To skip this check: $0 --no-root-check"
    fi
    
    log_success "Prerequisites check completed"
}

# Setup directory structure
setup_directories() {
    log_info "Setting up directory structure..."
    
    mkdir -p "$DOCKER_DIR"/{data,logs,certificates,backups,monitoring/{grafana/dashboards,grafana/datasources,fluentd}}
    
    # Set proper permissions
    chmod 755 "$DOCKER_DIR"/{data,logs,certificates,backups}
    chmod 700 "$DOCKER_DIR"/certificates
    
    log_success "Directory structure created"
}

# Generate environment file
generate_env_file() {
    local env_file="$DOCKER_DIR/.env"
    
    if [[ -f "$env_file" ]]; then
        log_warning "Environment file already exists: $env_file"
        read -p "Do you want to regenerate it? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return
        fi
    fi
    
    log_info "Generating environment configuration..."
    
    # Prompt for basic configuration
    read -p "DNS Server Domain [dns.netintegrate.net]: " dns_domain
    dns_domain=${dns_domain:-dns.netintegrate.net}
    
    read -p "Email for Let's Encrypt [admin@${dns_domain#dns.}]: " email
    email=${email:-admin@${dns_domain#dns.}}
    
    read -s -p "DNS Admin Password: " admin_password
    echo
    admin_password=${admin_password:-$(openssl rand -base64 32)}
    
    read -s -p "Certificate Password: " cert_password
    echo
    cert_password=${cert_password:-$(openssl rand -base64 32)}
    
    # Generate environment file
    cat > "$env_file" << EOF
# Technitium DNS Server Configuration
# Generated on $(date)

# Basic Configuration
DNS_ADMIN_PASSWORD=$admin_password
CERT_PASSWORD=$cert_password
DOMAINS=$dns_domain
EMAIL=$email

# Monitoring
GRAFANA_PASSWORD=$(openssl rand -base64 32)

# Backup
BACKUP_SCHEDULE=0 2 * * *
BACKUP_RETENTION_DAYS=30
BACKUP_PASSWORD=$(openssl rand -base64 32)

# Network
EXTERNAL_IP=192.168.1.100
INTERNAL_NETWORK=192.168.1.0/24

# Performance
CACHE_MAX_ENTRIES=100000
RECURSION_TIMEOUT=5000
RECURSION_RETRIES=2

# Security
ENABLE_DNSSEC=true
ENABLE_DNS_REBIND_PROTECTION=true
LOG_QUERIES=true
LOG_LEVEL=Info
EOF
    
    chmod 600 "$env_file"
    log_success "Environment file generated: $env_file"
}

# Generate certificates (if not using Let's Encrypt)
generate_certificates() {
    local cert_dir="$DOCKER_DIR/certificates"
    
    log_info "Checking for existing certificates..."
    
    if [[ -f "$cert_dir/dns.netintegrate.net_full_chain.pfx" ]]; then
        log_success "Certificates already exist"
        return
    fi
    
    log_info "Generating self-signed certificates for testing..."
    
    # Create CA
    openssl genrsa -out "$cert_dir/ca.key" 4096
    openssl req -new -x509 -key "$cert_dir/ca.key" -sha256 \
        -subj "/C=US/ST=State/L=City/O=NetIntegrate/CN=NetIntegrate Root CA" \
        -days 3650 -out "$cert_dir/ca.crt"
    
    # Generate server certificates
    for domain in dns.netintegrate.net dns2.netintegrate.net; do
        log_info "Generating certificate for $domain..."
        
        # Private key
        openssl genrsa -out "$cert_dir/$domain.key" 2048
        
        # Certificate signing request
        openssl req -new -key "$cert_dir/$domain.key" \
            -out "$cert_dir/$domain.csr" \
            -subj "/C=US/ST=State/L=City/O=NetIntegrate/CN=$domain"
        
        # Certificate
        openssl x509 -req -in "$cert_dir/$domain.csr" \
            -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" \
            -CAcreateserial -out "$cert_dir/$domain.crt" \
            -days 365 -sha256 \
            -extensions v3_req -extfile <(
                echo '[v3_req]'
                echo 'basicConstraints = CA:FALSE'
                echo 'keyUsage = nonRepudiation, digitalSignature, keyEncipherment'
                echo 'subjectAltName = @alt_names'
                echo '[alt_names]'
                echo "DNS.1 = $domain"
                echo "DNS.2 = *.$domain"
            )
        
        # Create PFX bundle
        openssl pkcs12 -export -out "$cert_dir/${domain}_full_chain.pfx" \
            -inkey "$cert_dir/$domain.key" \
            -in "$cert_dir/$domain.crt" \
            -certfile "$cert_dir/ca.crt" \
            -password pass:secure-cert-password-2024
        
        # Cleanup
        rm "$cert_dir/$domain.csr"
    done
    
    log_success "Self-signed certificates generated"
    log_warning "For production, replace with proper certificates from Let's Encrypt or CA"
}

# Deploy services
deploy_services() {
    log_info "Deploying Technitium DNS services..."
    
    cd "$DOCKER_DIR"
    
    # Pull latest images
    docker-compose pull
    
    # Start services
    docker-compose up -d
    
    # Wait for services to start
    log_info "Waiting for services to start..."
    sleep 30
    
    # Check service health
    if docker-compose ps | grep -q "Up"; then
        log_success "Services deployed successfully"
    else
        log_error "Some services failed to start"
        docker-compose logs
        exit 1
    fi
}

# Configure firewall
configure_firewall() {
    log_info "Configuring firewall rules..."
    
    if command -v ufw &> /dev/null; then
        # UFW (Ubuntu)
        ufw allow 53/udp comment "DNS UDP"
        ufw allow 53/tcp comment "DNS TCP"
        ufw allow 853/tcp comment "DNS-over-TLS"
        ufw allow 443/tcp comment "DNS-over-HTTPS"
        ufw allow 5380/tcp comment "DNS Console"
        log_success "UFW rules configured"
    elif command -v firewall-cmd &> /dev/null; then
        # Firewalld (CentOS/RHEL)
        firewall-cmd --permanent --add-port=53/udp
        firewall-cmd --permanent --add-port=53/tcp
        firewall-cmd --permanent --add-port=853/tcp
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --permanent --add-port=5380/tcp
        firewall-cmd --reload
        log_success "Firewalld rules configured"
    elif command -v iptables &> /dev/null; then
        # Direct iptables
        iptables -A INPUT -p udp --dport 53 -j ACCEPT
        iptables -A INPUT -p tcp --dport 53 -j ACCEPT
        iptables -A INPUT -p tcp --dport 853 -j ACCEPT
        iptables -A INPUT -p tcp --dport 443 -j ACCEPT
        iptables -A INPUT -p tcp --dport 5380 -j ACCEPT
        log_success "Iptables rules configured"
        log_warning "Remember to save iptables rules to persist across reboots"
    else
        log_warning "No supported firewall found. Please configure manually."
    fi
}

# Verify deployment
verify_deployment() {
    log_info "Verifying deployment..."
    
    # Check DNS resolution
    if nslookup google.com 127.0.0.1 &> /dev/null; then
        log_success "DNS resolution working"
    else
        log_error "DNS resolution failed"
    fi
    
    # Check web console
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:5380 | grep -q "200\|302"; then
        log_success "Web console accessible"
    else
        log_error "Web console not accessible"
    fi
    
    # Check monitoring
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:9090 | grep -q "200"; then
        log_success "Prometheus monitoring accessible"
    else
        log_warning "Prometheus monitoring not accessible"
    fi
    
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:3000 | grep -q "200\|302"; then
        log_success "Grafana dashboard accessible"
    else
        log_warning "Grafana dashboard not accessible"
    fi
}

# Show access information
show_access_info() {
    log_success "Deployment completed successfully!"
    echo
    echo "Access Information:"
    echo "=================="
    echo "DNS Server: localhost:53 or $(hostname -I | awk '{print $1}'):53"
    echo "Web Console: http://localhost:5380"
    echo "Monitoring:"
    echo "  - Prometheus: http://localhost:9090"
    echo "  - Grafana: http://localhost:3000"
    echo
    echo "Default Credentials:"
    echo "==================="
    echo "DNS Console: admin / [see .env file]"
    echo "Grafana: admin / [see .env file]"
    echo
    echo "Configuration Files:"
    echo "===================="
    echo "Environment: $DOCKER_DIR/.env"
    echo "DNS Config: $DOCKER_DIR/config/dns.config"
    echo "Certificates: $DOCKER_DIR/certificates/"
    echo "Logs: $DOCKER_DIR/logs/"
    echo "Backups: $DOCKER_DIR/backups/"
    echo
    echo "Next Steps:"
    echo "==========="
    echo "1. Change default passwords in web console"
    echo "2. Configure DNS zones and records"
    echo "3. Set up proper SSL certificates"
    echo "4. Configure monitoring alerts"
    echo "5. Test DNS resolution from clients"
    echo
}

# Cleanup function
cleanup() {
    log_info "Performing cleanup..."
    cd "$DOCKER_DIR"
    docker-compose down
    docker-compose rm -f
    log_success "Cleanup completed"
}

# Main execution
main() {
    case "${1:-}" in
        "start"|"deploy")
            check_prerequisites "$@"
            setup_directories
            generate_env_file
            generate_certificates
            deploy_services
            configure_firewall
            verify_deployment
            show_access_info
            ;;
        "stop")
            cd "$DOCKER_DIR"
            docker-compose down
            log_success "Services stopped"
            ;;
        "restart")
            cd "$DOCKER_DIR"
            docker-compose restart
            log_success "Services restarted"
            ;;
        "status")
            cd "$DOCKER_DIR"
            docker-compose ps
            ;;
        "logs")
            cd "$DOCKER_DIR"
            docker-compose logs -f "${2:-}"
            ;;
        "cleanup")
            cleanup
            ;;
        "update")
            cd "$DOCKER_DIR"
            docker-compose pull
            docker-compose up -d
            log_success "Services updated"
            ;;
        "backup")
            cd "$DOCKER_DIR"
            docker-compose exec backup /usr/local/bin/backup-dns.sh
            ;;
        "help"|"--help"|"-h")
            echo "Technitium DNS Server Docker Setup"
            echo
            echo "Usage: $0 [COMMAND]"
            echo
            echo "Commands:"
            echo "  start, deploy    Deploy and start all services"
            echo "  stop             Stop all services"
            echo "  restart          Restart all services"
            echo "  status           Show service status"
            echo "  logs [service]   Show logs (optionally for specific service)"
            echo "  update           Update and restart services"
            echo "  backup           Run manual backup"
            echo "  cleanup          Stop and remove all containers"
            echo "  help             Show this help message"
            echo
            ;;
        *)
            log_error "Unknown command: ${1:-}"
            echo "Use '$0 help' for usage information."
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
