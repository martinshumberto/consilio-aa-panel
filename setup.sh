#!/bin/bash

set -euo pipefail

# =========================
# ANSI COLOR CODES
# =========================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =========================
# CONFIGURABLE VARIABLES
# =========================
AA_PANEL_PORT=2086
AA_PANEL_INSTALL_SCRIPT="http://www.aapanel.com/script/install-ubuntu_6.0_en.sh"
S3_REMOTE_NAME="s3backup"
BACKUP_DIR="/mnt/data/backups"
WEB_DIR="/mnt/data/wwwroot"
MONGO_DIR="/mnt/data/mongodb"
REDIS_DIR="/mnt/data/redis"
POSTGRES_DIR="/mnt/data/postgres"
DOCKER_VOLUMES_DIR="/mnt/data/docker-volumes"
MAIL_DIR="/var/mail/vhosts"
NETDATA_INSTALL_URL="https://my-netdata.io/kickstart.sh"
SSL_EMAIL="admin@example.com"
HOSTNAME_FQDN=$(hostname -f)
# If hostname doesn't return FQDN, try to get domain from IP
if [[ "$HOSTNAME_FQDN" == "$(hostname -s)" ]]; then
    HOSTNAME_FQDN="$(hostname).example.com"
    echo -e "${YELLOW}WARNING: Could not determine FQDN. Using $HOSTNAME_FQDN${NC}"
fi

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Log file
LOGFILE="/var/log/aapanel-setup.log"

# =========================
# CHECK ROOT PRIVILEGES
# =========================
echo -e "${BLUE}🔍 Checking root privileges...${NC}"
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}❌ This script must be run as root${NC}"
    exit 1
fi

# =========================
# PREPARE LOG FILE
# =========================
echo -e "${BLUE}📝 Logging to $LOGFILE${NC}"
exec > >(tee -a "$LOGFILE") 2>&1
echo "Setup started at $(date)"

# =========================
# SYSTEM INFORMATION
# =========================
echo -e "${BLUE}🖥️ System Information:${NC}"
echo "Hostname: $(hostname)"
echo "FQDN: $HOSTNAME_FQDN"
echo "IP Address: $(curl -s ifconfig.me)"
echo "OS: $(lsb_release -ds)"
echo "Kernel: $(uname -r)"
echo "CPU: $(grep "model name" /proc/cpuinfo | head -n1 | cut -d: -f2 | sed 's/^\s*//')"
echo "Memory: $(free -h | grep Mem | awk '{print $2}')"
echo "Disk Space: $(df -h / | grep -v Filesystem | awk '{print $2}')"

# =========================
# SETUP SWAP
# =========================
echo -e "${BLUE}🔄 Setting up swap space...${NC}"

# Check if swap is already enabled
SWAP_ENABLED=$(free -m | grep Swap | awk '{print $2}')
if [ "$SWAP_ENABLED" -gt 100 ]; then
    echo -e "${GREEN}✅ Swap is already enabled ($SWAP_ENABLED MB)${NC}"
else
    # Calculate swap size (2GB or RAM size if less than 2GB)
    MEM_SIZE=$(free -m | grep Mem | awk '{print $2}')
    if [ "$MEM_SIZE" -lt 2048 ]; then
        SWAP_SIZE=$MEM_SIZE
    else
        SWAP_SIZE=2048
    fi
    
    echo "Creating $SWAP_SIZE MB swap file..."
    fallocate -l ${SWAP_SIZE}M /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    
    # Make swap permanent
    if ! grep -q "/swapfile" /etc/fstab; then
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
    fi
    
    # Configure swappiness
    echo "vm.swappiness=10" > /etc/sysctl.d/99-swappiness.conf
    sysctl -p /etc/sysctl.d/99-swappiness.conf
    
    # Configure vfs cache pressure
    echo "vm.vfs_cache_pressure=50" >> /etc/sysctl.d/99-swappiness.conf
    sysctl -p /etc/sysctl.d/99-swappiness.conf
    
    echo -e "${GREEN}✅ Swap file created and enabled${NC}"
fi

# =========================
# CREATE DIRECTORY STRUCTURE
# =========================
echo -e "${BLUE}📁 Creating directory structure...${NC}"
mkdir -p $BACKUP_DIR $WEB_DIR $MONGO_DIR $REDIS_DIR $POSTGRES_DIR $DOCKER_VOLUMES_DIR $MAIL_DIR /opt/aapanel

# Set appropriate permissions
chown -R www-data:www-data $WEB_DIR
chmod -R 755 $WEB_DIR

# =========================
# INSTALL BASIC DEPENDENCIES
# =========================
echo -e "${BLUE}📦 Installing basic dependencies...${NC}"
apt update
apt install -y curl wget unzip git ufw fail2ban software-properties-common rclone \
  docker.io docker-compose certbot bc apt-transport-https ca-certificates \
  lsb-release logrotate iptables python3-certbot-nginx htop iotop ncdu \
  nethogs net-tools dnsutils cron chrony rsync duplicity openssl libapache2-mod-security2 \
  zip unzip logwatch

# =========================
# SYSTEM TUNING
# =========================
echo -e "${BLUE}⚙️ Tuning system for better performance...${NC}"

# Increase file limits
cat > /etc/security/limits.d/99-nofiles.conf << EOF
*               soft    nofile          65535
*               hard    nofile          65535
root            soft    nofile          65535
root            hard    nofile          65535
EOF

# Tune network parameters for better performance
cat > /etc/sysctl.d/99-network-tune.conf << EOF
# Increase TCP max buffer size setable using setsockopt()
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216

# Increase Linux auto-tuning TCP buffer limits
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Increase TCP max connections
net.core.somaxconn = 65535

# Increase the maximum amount of option memory buffers
net.core.optmem_max = 65535

# Enable TCP Fast Open
net.ipv4.tcp_fastopen = 3

# Protect against SYN flood attacks
net.ipv4.tcp_syncookies = 1
EOF

# Apply sysctl settings
sysctl -p /etc/sysctl.d/99-network-tune.conf

# =========================
# INSTALL AAPANEL IF NOT EXISTS
# =========================
echo -e "${BLUE}🔧 Installing aaPanel...${NC}"
if [ ! -d "/www/server/panel" ]; then
  wget -O install.sh "$AA_PANEL_INSTALL_SCRIPT"
  echo -e "${YELLOW}Installing aaPanel...${NC}"
  bash install.sh <<EOF
Y
EOF
  # Set custom port for aaPanel
  if [ -f "/www/server/panel/data/port.pl" ]; then
    echo -e "${YELLOW}Changing aaPanel port to $AA_PANEL_PORT...${NC}"
    echo "$AA_PANEL_PORT" > /www/server/panel/data/port.pl
    bt reload
  fi
  echo -e "${GREEN}✅ aaPanel installed at port $AA_PANEL_PORT${NC}"
else
  echo -e "${GREEN}✅ aaPanel already installed${NC}"
  # Update port if needed
  CURRENT_PORT=$(cat /www/server/panel/data/port.pl)
  if [ "$CURRENT_PORT" != "$AA_PANEL_PORT" ]; then
    echo -e "${YELLOW}Changing aaPanel port from $CURRENT_PORT to $AA_PANEL_PORT...${NC}"
    echo "$AA_PANEL_PORT" > /www/server/panel/data/port.pl
    bt reload
  fi
fi

# =========================
# BACKUP PANEL CONFIG
# =========================
echo -e "${BLUE}💾 Backing up initial aaPanel configuration...${NC}"
if [ -d "/www/server/panel" ]; then
  mkdir -p "$BACKUP_DIR/panel"
  tar -czf "$BACKUP_DIR/panel/panel_initial_backup_$(date +%Y%m%d).tar.gz" -C /www/server/panel .
  echo -e "${GREEN}✅ aaPanel configuration backed up${NC}"
fi

# Copy support files to /opt/aapanel
echo -e "${BLUE}📂 Copying support files...${NC}"
if [ -f "$SCRIPT_DIR/docker-compose.yaml" ]; then
  cp "$SCRIPT_DIR/docker-compose.yaml" /opt/aapanel/docker-compose.yaml
else
  # Create docker-compose.yaml if doesn't exist
  cat > /opt/aapanel/docker-compose.yaml << EOF
version: '3.8'

services:
  mongodb:
    image: mongo:4.4
    container_name: aapanel-mongodb
    restart: always
    environment:
      - MONGO_INITDB_ROOT_USERNAME=admin
      - MONGO_INITDB_ROOT_PASSWORD=\${MONGO_PASSWORD:-strongpassword}
    volumes:
      - /mnt/data/mongodb:/data/db
    networks:
      - aapanel-net
    ports:
      - "127.0.0.1:27017:27017"
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "3"
    labels:
      com.backup: "true"

  redis:
    image: redis:6-alpine
    container_name: aapanel-redis
    restart: always
    command: redis-server --requirepass \${REDIS_PASSWORD:-strongpassword}
    volumes:
      - /mnt/data/redis:/data
    networks:
      - aapanel-net
    ports:
      - "127.0.0.1:6379:6379"
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "3"
    labels:
      com.backup: "true"

networks:
  aapanel-net:
    external: true
EOF
fi

# Copy other scripts or create if they don't exist
for script in backup.sh security-hardening.sh postfix-config.sh monitoring.sh; do
  if [ -f "$SCRIPT_DIR/$script" ]; then
    cp "$SCRIPT_DIR/$script" /opt/aapanel/$script
  else
    echo "Warning: $script not found in $SCRIPT_DIR. Will be created later."
  fi
done

# Ensure all scripts are executable
chmod +x /opt/aapanel/*.sh 2>/dev/null || true

# Create rclone config example if not exists
if [ ! -f "/opt/aapanel/rclone.conf.example" ]; then
  cat > /opt/aapanel/rclone.conf.example << EOF
# Example rclone.conf file for S3 backups
# Place this in /root/.config/rclone/rclone.conf or ~/.config/rclone/rclone.conf

[s3backup]
type = s3
provider = AWS
access_key_id = YOUR_ACCESS_KEY_ID
secret_access_key = YOUR_SECRET_ACCESS_KEY
region = us-east-1
location_constraint = us-east-1
acl = private

# For MinIO/other S3-compatible storage:
# type = s3
# provider = Other
# env_auth = false
# access_key_id = YOUR_ACCESS_KEY
# secret_access_key = YOUR_SECRET_KEY
# endpoint = https://your-endpoint.com
# acl = private
EOF
fi

# =========================
# CONFIGURE SSL FOR PANEL
# =========================
echo -e "${BLUE}🔒 Setting up SSL for aaPanel...${NC}"
if [ -f "/www/server/panel/data/domain.conf" ]; then
  PANEL_DOMAIN=$(cat /www/server/panel/data/domain.conf)
  if [ -n "$PANEL_DOMAIN" ]; then
    echo -e "${YELLOW}aaPanel domain is set to: $PANEL_DOMAIN${NC}"
    
    # Check if SSL is already enabled
    if [ -f "/www/server/panel/data/ssl.pl" ]; then
      echo -e "${GREEN}✅ SSL is already enabled for the panel${NC}"
    else
      echo -e "${YELLOW}Setting up Let's Encrypt SSL for aaPanel...${NC}"
      
      # Stop nginx before running certbot
      systemctl stop nginx 2>/dev/null || true
      
      # Using certbot for SSL
      certbot certonly --standalone --non-interactive --agree-tos \
        --email $SSL_EMAIL -d $PANEL_DOMAIN
      
      # Configure SSL for panel
      if [ -d "/etc/letsencrypt/live/$PANEL_DOMAIN" ]; then
        # Create SSL directory
        mkdir -p /www/server/panel/ssl
        
        # Copy certificates
        cp /etc/letsencrypt/live/$PANEL_DOMAIN/cert.pem /www/server/panel/ssl/certificate.pem
        cp /etc/letsencrypt/live/$PANEL_DOMAIN/privkey.pem /www/server/panel/ssl/privateKey.pem
        
        # Enable SSL for panel
        echo "True" > /www/server/panel/data/ssl.pl
        
        # Create auto-renew hook
        mkdir -p /etc/letsencrypt/renewal-hooks/post
        cat > /etc/letsencrypt/renewal-hooks/post/aapanel-ssl.sh << EOF
#!/bin/bash
# Hook to update aaPanel SSL certificates after renewal

DOMAIN="$PANEL_DOMAIN"
PANEL_SSL_DIR="/www/server/panel/ssl"

# Copy renewed certificates
cp /etc/letsencrypt/live/$DOMAIN/cert.pem $PANEL_SSL_DIR/certificate.pem
cp /etc/letsencrypt/live/$DOMAIN/privkey.pem $PANEL_SSL_DIR/privateKey.pem

# Restart panel to apply new certificates
bt restart panel
EOF
        chmod +x /etc/letsencrypt/renewal-hooks/post/aapanel-ssl.sh
        
        # Start nginx and restart panel
        systemctl start nginx 2>/dev/null || true
        bt restart panel
        
        echo -e "${GREEN}✅ SSL enabled for aaPanel with auto-renewal${NC}"
      else
        echo -e "${RED}❌ Failed to obtain SSL certificate for $PANEL_DOMAIN${NC}"
        echo -e "${YELLOW}⚠️ Please ensure your domain points to this server's IP and ports 80/443 are open.${NC}"
      fi
    fi
  else
    echo -e "${YELLOW}⚠️ No domain set for aaPanel. SSL setup skipped.${NC}"
    echo -e "${YELLOW}⚠️ Set a domain in the panel and run this script again to enable SSL.${NC}"
    echo -e "${YELLOW}⚠️ You can set a domain with: echo 'yourdomain.com' > /www/server/panel/data/domain.conf${NC}"
  fi
else
  echo -e "${YELLOW}⚠️ Domain configuration not found. SSL setup skipped.${NC}"
fi

# =========================
# ENHANCE PANEL SECURITY
# =========================
echo -e "${BLUE}🔒 Enhancing aaPanel security...${NC}"

# Secure session settings
if [ -f "/www/server/panel/class/session.py" ]; then
  # Backup original file
  cp /www/server/panel/class/session.py /www/server/panel/class/session.py.bak
  
  # Set more secure session timeout (8 hours instead of default 24 hours)
  sed -i 's/SESSION_TIMEOUT = 86400/SESSION_TIMEOUT = 28800/' /www/server/panel/class/session.py
  
  # Enforce secure cookies if SSL is enabled
  if [ -f "/www/server/panel/data/ssl.pl" ]; then
    sed -i "s/'secure': False/'secure': True/" /www/server/panel/class/session.py
    sed -i "s/'httponly': False/'httponly': True/" /www/server/panel/class/session.py
  fi
  
  echo -e "${GREEN}✅ Panel session security enhanced${NC}"
fi

# =========================
# CONFIGURE FIREWALL
# =========================
echo -e "${BLUE}🔥 Configuring firewall...${NC}"

# Reset UFW
ufw --force reset

# Set default policies
ufw default deny incoming
ufw default allow outgoing

# Allow essential services
ufw allow ssh comment 'SSH'
ufw allow $AA_PANEL_PORT/tcp comment 'aaPanel'
ufw allow http comment 'HTTP'
ufw allow https comment 'HTTPS'
ufw allow 25/tcp comment 'SMTP'
ufw allow 465/tcp comment 'SMTPS'
ufw allow 587/tcp comment 'Submission'
ufw allow 110/tcp comment 'POP3'
ufw allow 995/tcp comment 'POP3S'
ufw allow 143/tcp comment 'IMAP'
ufw allow 993/tcp comment 'IMAPS'

# Optional database ports - restricted to localhost only
ufw allow from 127.0.0.1 to any port 3306 comment 'MySQL/MariaDB-local'
ufw allow from 127.0.0.1 to any port 5432 comment 'PostgreSQL-local'
ufw allow from 127.0.0.1 to any port 27017 comment 'MongoDB-local'
ufw allow from 127.0.0.1 to any port 6379 comment 'Redis-local'

# Allow Netdata dashboard
ufw allow 19999/tcp comment 'Netdata'

# Enable UFW
echo -e "${YELLOW}Enabling UFW firewall...${NC}"
ufw --force enable
ufw status verbose

# Configure iptables persistent
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
apt install -y iptables-persistent

# Save current iptables rules
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

# =========================
# FAIL2BAN CONFIGURATION
# =========================
echo -e "${BLUE}🔒 Configuring Fail2Ban...${NC}"

# Install fail2ban if not already installed
if ! command -v fail2ban-client &> /dev/null; then
  apt install -y fail2ban
fi

# Create custom configuration
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# Ban hosts for 1 hour
bantime = 3600
# Check for 10 minutes
findtime = 600
# Ban after 5 attempts
maxretry = 5
# Email notification (when email is set up)
destemail = root@localhost
sendername = Fail2Ban
mta = mail
action = %(action_mwl)s

# SSH protection
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

# aaPanel protection
[aapanel]
enabled = true
port = $AA_PANEL_PORT
filter = aapanel
logpath = /www/server/panel/logs/request/*.log
maxretry = 5

# Web protection
[apache]
enabled = true
port = http,https
filter = apache-auth
logpath = /www/wwwlogs/*error.log
maxretry = 5

[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /www/wwwlogs/*error.log
maxretry = 5

[nginx-botsearch]
enabled = true
port = http,https
filter = nginx-botsearch
logpath = /www/wwwlogs/*error.log
maxretry = 2
findtime = 300
bantime = 7200

[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /www/wwwlogs/*error.log
maxretry = 2
findtime = 300
bantime = 86400
EOF

# Create custom filter for aaPanel
cat > /etc/fail2ban/filter.d/aapanel.conf << EOF
[Definition]
failregex = ^.* ((Username|Unauthorized|Invalid)), ip: <HOST>.*$
ignoreregex =
EOF

# Create custom filter for bad bots
cat > /etc/fail2ban/filter.d/nginx-badbots.conf << EOF
[Definition]
failregex = ^.*"(GET|POST|HEAD).*HTTP.*"(?:Sogou web spider|AhrefsBot|YandexBot|MJ12bot|SemrushBot|LinkpadBot).*$
ignoreregex =
EOF

# Enable and restart fail2ban
systemctl enable fail2ban
systemctl restart fail2ban

echo -e "${GREEN}✅ Fail2Ban configured${NC}"

# =========================
# CONFIGURE MODSECURITY WITH NGINX
# =========================
echo -e "${BLUE}🔒 Setting up ModSecurity with OWASP CRS...${NC}"

# Check if Nginx is installed by aaPanel
if [ -d "/www/server/nginx" ]; then
  echo -e "${YELLOW}aaPanel Nginx detected, installing ModSecurity...${NC}"
  
  # Install dependencies
  apt install -y libmodsecurity3 libapache2-mod-security2
  
  # Download and compile ModSecurity Nginx connector
  cd /usr/local/src
  git clone --depth 1 -b v1.0.1 https://github.com/SpiderLabs/ModSecurity-nginx.git
  
  # Get Nginx version
  NGINX_VERSION=$(nginx -v 2>&1 | grep -o '[0-9]\.[0-9]\+\.[0-9]\+')
  
  # Download the same version of Nginx source
  wget http://nginx.org/download/nginx-$NGINX_VERSION.tar.gz
  tar -xzvf nginx-$NGINX_VERSION.tar.gz
  
  # Get Nginx compile options
  NGINX_OPTIONS=$(nginx -V 2>&1 | grep -o 'configure arguments:.*' | sed 's/configure arguments://')
  
  # Compile Nginx with ModSecurity
  cd nginx-$NGINX_VERSION
  ./configure $NGINX_OPTIONS --add-dynamic-module=/usr/local/src/ModSecurity-nginx
  make modules
  
  # Copy the module to Nginx modules directory
  mkdir -p /www/server/nginx/modules/
  cp objs/ngx_http_modsecurity_module.so /www/server/nginx/modules/
  
  # Clone OWASP Core Rule Set
  git clone https://github.com/coreruleset/coreruleset.git /www/server/nginx/conf/modsec-crs
  cd /www/server/nginx/conf/modsec-crs
  cp crs-setup.conf.example crs-setup.conf
  
  # Configure ModSecurity
  mkdir -p /www/server/nginx/conf/modsec
  cat > /www/server/nginx/conf/modsec/modsecurity.conf << EOF
# Basic ModSecurity configuration
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_HEADERS:Content-Type "text/xml" \
     "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyInMemoryLimit 131072
SecRequestBodyLimitAction Reject
SecRule REQBODY_ERROR "!@eq 0" \
     "id:'200001',phase:2,t:none,deny,status:400,log,msg:'Failed to parse request body.'"
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html text/xml
SecResponseBodyLimit 524288
SecResponseBodyLimitAction ProcessPartial
SecTmpDir /tmp/
SecDataDir /tmp/
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABIJDEFHZ
SecArgumentSeparator &
SecCookieFormat 0
SecUnicodeMapFile unicode.mapping 20127
SecStatusEngine On
EOF

  # Create main ModSecurity configuration file
  cat > /www/server/nginx/conf/modsec/main.conf << EOF
Include "/www/server/nginx/conf/modsec/modsecurity.conf"
Include "/www/server/nginx/conf/modsec-crs/crs-setup.conf"
Include "/www/server/nginx/conf/modsec-crs/rules/*.conf"
EOF

  # Add ModSecurity configuration to Nginx
  if [ -f "/www/server/nginx/conf/nginx.conf" ]; then
    # Backup original file
    cp /www/server/nginx/conf/nginx.conf /www/server/nginx/conf/nginx.conf.bak
    
    # Add module loading directive
    sed -i '1i load_module modules/ngx_http_modsecurity_module.so;' /www/server/nginx/conf/nginx.conf
    
    # Add ModSecurity directives to http section
    sed -i '/http {/a \    modsecurity on;\n    modsecurity_rules_file /www/server/nginx/conf/modsec/main.conf;' /www/server/nginx/conf/nginx.conf
    
    echo -e "${GREEN}✅ ModSecurity with OWASP CRS installed for Nginx${NC}"
  else
    echo -e "${YELLOW}⚠️ Nginx configuration not found. ModSecurity setup incomplete.${NC}"
  fi
else
  echo -e "${YELLOW}⚠️ aaPanel Nginx not detected. Install Nginx from the panel first.${NC}"
  echo -e "${YELLOW}⚠️ Then run this script again.${NC}"
fi

# =========================
# SECURE SHARED MEMORY
# =========================
echo -e "${BLUE}🔒 Securing shared memory...${NC}"
if ! grep -q "/dev/shm" /etc/fstab; then
  echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
  echo -e "${GREEN}✅ Shared memory secured${NC}"
fi

# =========================
# SETUP AUTOMATED SECURITY UPDATES
# =========================
echo -e "${BLUE}🔧 Setting up unattended security updates...${NC}"

apt install -y unattended-upgrades apt-listchanges

# Configure unattended upgrades
cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF

# Enable daily upgrades
cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

# =========================
# SECURE SSH CONFIG
# =========================
echo -e "${BLUE}🔧 Securing SSH configuration...${NC}"

# Backup original config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Secure SSH config (but keep root login for now)
cat > /etc/ssh/sshd_config << EOF
# Security hardened SSH config
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Authentication
LoginGraceTime 30
PermitRootLogin prohibit-password
StrictModes yes
MaxAuthTries 3
MaxSessions 5

# Only use modern algorithms
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# Features
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PrintMotd no
PermitUserEnvironment no
PermitEmptyPasswords no
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes

# Idle timeout (30 minutes)
ClientAliveInterval 300
ClientAliveCountMax 6
EOF

# Restart SSH (carefully, to avoid disconnection issues)
echo -e "${YELLOW}⚠️ SSH will restart in 5 seconds. This may disconnect your current session.${NC}"
sleep 5
systemctl restart sshd

# =========================
# RCLONE CONFIGURATION
# =========================
echo -e "${BLUE}💾 Setting up rclone...${NC}"

if ! command -v rclone &> /dev/null; then
  echo -e "${YELLOW}Installing rclone...${NC}"
  curl https://rclone.org/install.sh | bash
fi

echo -e "${YELLOW}rclone example configuration file created at /opt/aapanel/rclone.conf.example${NC}"
echo -e "${YELLOW}Configure rclone with: rclone config${NC}"

# =========================
# DOCKER CONFIGURATION
# =========================
echo -e "${BLUE}🐳 Setting up Docker...${NC}"

# Enable and start Docker
systemctl enable docker
systemctl start docker

# Create Docker network
docker network inspect aapanel-net &>/dev/null || docker network create aapanel-net
echo -e "${GREEN}✅ Docker network 'aapanel-net' created${NC}"

# Set environment variables for docker-compose
DB_PASSWORD=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
REDIS_PASSWORD=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)

# Replace passwords in docker-compose.yaml
sed -i "s/MONGO_PASSWORD:-strongpassword/MONGO_PASSWORD:-${DB_PASSWORD}/g" /opt/aapanel/docker-compose.yaml
sed -i "s/REDIS_PASSWORD:-strongpassword/REDIS_PASSWORD:-${REDIS_PASSWORD}/g" /opt/aapanel/docker-compose.yaml

# Start containers
cd /opt/aapanel
docker-compose up -d

echo -e "${GREEN}✅ Docker containers started with the following credentials:${NC}"
echo -e "MongoDB Admin Password: ${DB_PASSWORD}"
echo -e "Redis Password: ${REDIS_PASSWORD}"
echo -e "These credentials are saved in /opt/aapanel/docker-compose.yaml"

# Create a script to manage dockerized services
cat > /opt/aapanel/docker-manager.sh << 'EOF'
#!/bin/bash

# Docker service manager script
set -e

SERVICE=$1
ACTION=$2

# Display usage if parameters are missing
if [ -z "$SERVICE" ] || [ -z "$ACTION" ]; then
  echo "Usage: $0 SERVICE ACTION"
  echo "Services: mongodb, redis, postgres, all"
  echo "Actions: start, stop, restart, status, logs"
  exit 1
fi

# Function to manage all services
manage_all() {
  case "$1" in
    start)
      cd /opt/aapanel && docker-compose up -d
      ;;
    stop)
      cd /opt/aapanel && docker-compose down
      ;;
    restart)
      cd /opt/aapanel && docker-compose restart
      ;;
    status)
      docker-compose ps
      ;;
    logs)
      docker-compose logs
      ;;
    *)
      echo "Invalid action for all services"
      exit 1
      ;;
  esac
}

# Function to manage specific service
manage_service() {
  local service=$1
  local action=$2
  
  case "$action" in
    start)
      cd /opt/aapanel && docker-compose up -d $service
      ;;
    stop)
      cd /opt/aapanel && docker-compose stop $service
      ;;
    restart)
      cd /opt/aapanel && docker-compose restart $service
      ;;
    status)
      docker-compose ps $service
      ;;
    logs)
      docker-compose logs $service
      ;;
    *)
      echo "Invalid action for $service"
      exit 1
      ;;
  esac
}

# Main logic
if [ "$SERVICE" = "all" ]; then
  manage_all "$ACTION"
else
  # Check if service exists
  if ! grep -q "$SERVICE:" /opt/aapanel/docker-compose.yaml; then
    echo "Service $SERVICE not found in docker-compose.yaml"
    exit 1
  fi
  manage_service "$SERVICE" "$ACTION"
fi

echo "Done."
EOF

chmod +x /opt/aapanel/docker-manager.sh

# =========================
# POSTGRESQL SETUP
# =========================
echo -e "${BLUE}🐘 Setting up PostgreSQL...${NC}"

# Check if exists in aaPanel's plugin directory
if [ ! -d "/www/server/panel/plugin/postgresql" ]; then
  echo -e "${YELLOW}PostgreSQL plugin not found in aaPanel. Setting up via Docker...${NC}"
  
  # Add PostgreSQL to docker-compose.yaml
  if ! grep -q "postgres:" /opt/aapanel/docker-compose.yaml; then
    # Create a backup of current docker-compose.yaml
    cp /opt/aapanel/docker-compose.yaml /opt/aapanel/docker-compose.yaml.bak
    
    # Generate a password for PostgreSQL
    PG_PASSWORD=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
    
    # Insert PostgreSQL service before the last 'networks:' line
    sed -i '/networks:/i \  postgres:\n    image: postgres:13-alpine\n    container_name: aapanel-postgres\n    restart: always\n    environment:\n      - POSTGRES_PASSWORD='${PG_PASSWORD}'\n      - POSTGRES_USER=postgres\n      - POSTGRES_DB=postgres\n    volumes:\n      - /mnt/data/postgres:/var/lib/postgresql/data\n    networks:\n      - aapanel-net\n    ports:\n      - "127.0.0.1:5432:5432"\n    logging:\n      driver: "json-file"\n      options:\n        max-size: "100m"\n        max-file: "3"\n    labels:\n      com.backup: "true"\n' /opt/aapanel/docker-compose.yaml
    
    # Restart all containers to include PostgreSQL
    cd /opt/aapanel
    docker-compose up -d
    
    echo -e "${GREEN}✅ PostgreSQL container started with the following credentials:${NC}"
    echo -e "PostgreSQL Admin Password: ${PG_PASSWORD}"
    echo -e "PostgreSQL User: postgres"
    echo -e "PostgreSQL Host: 127.0.0.1"
    echo -e "PostgreSQL Port: 5432"
  else
    echo -e "${GREEN}✅ PostgreSQL already in docker-compose.yaml${NC}"
  fi
else
  echo -e "${GREEN}✅ PostgreSQL plugin already installed in aaPanel${NC}"
fi

# =========================
# INSTALL NETDATA
# =========================
echo -e "${BLUE}📊 Installing Netdata monitoring...${NC}"
if [ ! -d "/opt/netdata" ] && [ ! -d "/usr/libexec/netdata" ]; then
  bash <(curl -Ss $NETDATA_INSTALL_URL) --dont-wait --stable-channel --disable-telemetry
  
  # Configure Netdata retention (7 days)
  if [ -f "/etc/netdata/netdata.conf" ]; then
    sed -i 's/# history = 3996/history = 10080/g' /etc/netdata/netdata.conf
  fi
  
  echo -e "${GREEN}✅ Netdata installed${NC}"
  echo -e "Access Netdata dashboard at: http://$(hostname -I | awk '{print $1}'):19999"
else
  echo -e "${GREEN}✅ Netdata already installed${NC}"
fi

# =========================
# SET UP BACKUP CRON JOB
# =========================
echo -e "${BLUE}🔄 Setting up backup cron job...${NC}"
if ! grep -q "backup-aapanel" /etc/crontab; then
  echo "0 2 * * * root bash /opt/aapanel/backup.sh >> /var/log/backup-aapanel.log 2>&1" >> /etc/crontab
  echo -e "${GREEN}✅ Backup cron job added${NC}"
else
  echo -e "${GREEN}✅ Backup cron job already exists${NC}"
fi

# Create backup.sh if it doesn't exist
if [ ! -f "/opt/aapanel/backup.sh" ]; then
  echo -e "${YELLOW}Creating backup script...${NC}"
  cat > /opt/aapanel/backup.sh << 'EOF'
#!/bin/bash

set -euo pipefail

# =========================
# BACKUP CONFIGURATION
# =========================
DATE=$(date +%Y-%m-%d_%H-%M-%S)
BACKUP_DIR="/mnt/data/backups"
WEB_DIR="/mnt/data/wwwroot"
PANEL_DIR="/www/server/panel"
MAIL_DIR="/var/mail"
S3_REMOTE_NAME="s3backup"
RETENTION_DAYS=7

# Ensure backup directory exists
mkdir -p "${BACKUP_DIR}"
mkdir -p "${BACKUP_DIR}/mysql"
mkdir -p "${BACKUP_DIR}/mongodb"
mkdir -p "${BACKUP_DIR}/postgres"
mkdir -p "${BACKUP_DIR}/panel"
mkdir -p "${BACKUP_DIR}/web"
mkdir -p "${BACKUP_DIR}/mail"

echo "Backup starting at $(date)"

# =========================
# MYSQL BACKUPS
# =========================
if command -v mysql &> /dev/null; then
  echo "Backing up MySQL databases..."
  # Get MySQL credentials from the panel
  if [ -f "/www/server/panel/config/config.json" ]; then
    MYSQL_USER=$(grep -o '"mysql_root":[^,}]*' /www/server/panel/config/config.json | cut -d'"' -f4)
    MYSQL_PASSWORD=$(grep -o '"mysql_root_pwd":[^,}]*' /www/server/panel/config/config.json | cut -d'"' -f4)
    
    # Get all databases
    MYSQL_DBS=$(mysql -u${MYSQL_USER} -p${MYSQL_PASSWORD} -e "SHOW DATABASES;" | grep -Ev "(Database|information_schema|performance_schema|mysql)")
    
    # Backup each database
    for DB in $MYSQL_DBS; do
      echo "  - Backing up MySQL DB: $DB"
      mysqldump -u${MYSQL_USER} -p${MYSQL_PASSWORD} --single-transaction --quick --lock-tables=false $DB | gzip > "${BACKUP_DIR}/mysql/${DB}_${DATE}.sql.gz"
    done
  else
    echo "  ⚠️ MySQL credentials not found. Skipping MySQL backups."
  fi
else
  echo "  ⚠️ MySQL not installed. Skipping MySQL backups."
fi

# =========================
# POSTGRESQL BACKUPS
# =========================
if command -v psql &> /dev/null; then
  echo "Backing up PostgreSQL databases..."
  if [ -f "/www/server/panel/plugin/postgresql/config.json" ]; then
    PG_USER=$(grep -o '"username":[^,}]*' /www/server/panel/plugin/postgresql/config.json | cut -d'"' -f4)
    PG_PASSWORD=$(grep -o '"password":[^,}]*' /www/server/panel/plugin/postgresql/config.json | cut -d'"' -f4)
    
    # Get all databases
    export PGPASSWORD=$PG_PASSWORD
    PG_DBS=$(psql -U $PG_USER -c "SELECT datname FROM pg_database WHERE datistemplate = false AND datname != 'postgres';" -t | tr -d ' ')
    
    # Backup each database
    for DB in $PG_DBS; do
      echo "  - Backing up PostgreSQL DB: $DB"
      pg_dump -U $PG_USER $DB | gzip > "${BACKUP_DIR}/postgres/${DB}_${DATE}.sql.gz"
    done
    unset PGPASSWORD
  else
    # Try Docker PostgreSQL
    if docker ps | grep -q aapanel-postgres; then
      echo "  - Using Docker PostgreSQL"
      PG_PASSWORD=$(grep -o 'POSTGRES_PASSWORD=[^"]*' /opt/aapanel/docker-compose.yaml | cut -d'=' -f2)
      
      # Get all databases
      docker exec -i aapanel-postgres psql -U postgres -c "SELECT datname FROM pg_database WHERE datistemplate = false AND datname != 'postgres';" -t | while read DB; do
        DB=$(echo $DB | tr -d ' ')
        if [ -n "$DB" ]; then
          echo "  - Backing up PostgreSQL DB: $DB"
          docker exec -i aapanel-postgres pg_dump -U postgres $DB | gzip > "${BACKUP_DIR}/postgres/${DB}_${DATE}.sql.gz"
        fi
      done
    else
      echo "  ⚠️ PostgreSQL credentials not found. Skipping PostgreSQL backups."
    fi
  fi
else
  if docker ps | grep -q aapanel-postgres; then
    echo "  - Using Docker PostgreSQL"
    PG_PASSWORD=$(grep -o 'POSTGRES_PASSWORD=[^"]*' /opt/aapanel/docker-compose.yaml | cut -d'=' -f2)
    
    # Get all databases
    docker exec -i aapanel-postgres psql -U postgres -c "SELECT datname FROM pg_database WHERE datistemplate = false AND datname != 'postgres';" -t | while read DB; do
      DB=$(echo $DB | tr -d ' ')
      if [ -n "$DB" ]; then
        echo "  - Backing up PostgreSQL DB: $DB"
        docker exec -i aapanel-postgres pg_dump -U postgres $DB | gzip > "${BACKUP_DIR}/postgres/${DB}_${DATE}.sql.gz"
      fi
    done
  else
    echo "  ⚠️ PostgreSQL not installed. Skipping PostgreSQL backups."
  fi
fi

# =========================
# MONGODB BACKUPS
# =========================
if command -v mongodump &> /dev/null && docker ps | grep -q aapanel-mongodb; then
  echo "Backing up MongoDB databases..."
  # Get MongoDB password from environment or docker-compose
  MONGO_PASSWORD=$(grep -o 'MONGO_PASSWORD:-[^}]*' /opt/aapanel/docker-compose.yaml | cut -d'-' -f2 | sed 's/}//')
  if [ -z "$MONGO_PASSWORD" ]; then
    MONGO_PASSWORD="strongpassword"
  fi
  
  MONGO_DUMP_DIR="${BACKUP_DIR}/mongodb/dump_${DATE}"
  mkdir -p "$MONGO_DUMP_DIR"
  
  # Using mongodump to backup all databases
  mongodump --host localhost --port 27017 --username admin --password $MONGO_PASSWORD --authenticationDatabase admin --out $MONGO_DUMP_DIR
  
  # Compress the dump
  cd "${BACKUP_DIR}/mongodb"
  tar -czf "mongodb_${DATE}.tar.gz" "dump_${DATE}"
  rm -rf "dump_${DATE}"
  
  echo "  ✅ MongoDB backup completed"
else
  echo "  ⚠️ MongoDB not available. Skipping MongoDB backups."
fi

# =========================
# AAPANEL BACKUP
# =========================
echo "Backing up aaPanel configuration..."
if [ -d "$PANEL_DIR" ]; then
  tar -czf "${BACKUP_DIR}/panel/panel_config_${DATE}.tar.gz" -C "$PANEL_DIR" .
  echo "  ✅ aaPanel backup completed"
else
  echo "  ⚠️ aaPanel directory not found. Skipping panel backup."
fi

# =========================
# WEB DATA BACKUP
# =========================
echo "Backing up web files..."
if [ -d "$WEB_DIR" ]; then
  # Excluding large files and temp files
  tar --exclude="*.log" --exclude="*.tmp" --exclude=".git" --exclude="node_modules" \
    -czf "${BACKUP_DIR}/web/web_data_${DATE}.tar.gz" -C "$WEB_DIR" .
  echo "  ✅ Web data backup completed"
else
  echo "  ⚠️ Web directory not found. Skipping web backup."
fi

# =========================
# MAIL BACKUP
# =========================
echo "Backing up mail data..."
if [ -d "$MAIL_DIR" ]; then
  tar -czf "${BACKUP_DIR}/mail/mail_data_${DATE}.tar.gz" -C "$MAIL_DIR" .
  echo "  ✅ Mail data backup completed"
else
  echo "  ⚠️ Mail directory not found. Skipping mail backup."
fi

# =========================
# S3 SYNC
# =========================
echo "Syncing backups to S3..."
if command -v rclone &> /dev/null && rclone listremotes | grep -q "$S3_REMOTE_NAME:"; then
  rclone sync "${BACKUP_DIR}" "${S3_REMOTE_NAME}:aapanel-backups/${HOSTNAME}" \
    --progress --stats-one-line --stats 15s
  echo "  ✅ S3 sync completed"
else
  echo "  ⚠️ Rclone not configured with $S3_REMOTE_NAME remote. Skipping S3 sync."
  echo "      Configure with: rclone config"
fi

# =========================
# CLEANUP OLD BACKUPS
# =========================
echo "Cleaning up old backups (older than ${RETENTION_DAYS} days)..."
find "${BACKUP_DIR}" -type f -mtime +${RETENTION_DAYS} -name "*.gz" -delete
find "${BACKUP_DIR}" -type f -mtime +${RETENTION_DAYS} -name "*.sql.gz" -delete

echo "Backup completed at $(date)" 
EOF
  chmod +x /opt/aapanel/backup.sh
fi

# =========================
# EMAIL SERVER SETUP
# =========================
echo -e "${BLUE}📧 Setting up Email Server...${NC}"

# Ask about mail server
echo -e "${YELLOW}Do you want to set up a mail server with Postfix, Dovecot, and DKIM/SPF/DMARC? (y/n)${NC}"
read -r SETUP_MAIL
if [[ "$SETUP_MAIL" =~ ^[Yy]$ ]]; then
  echo -e "${YELLOW}Setting up mail server...${NC}"
  
  # Create mail server setup script if it doesn't exist
  if [ ! -f "/opt/aapanel/postfix-config.sh" ]; then
    cat > /opt/aapanel/postfix-config.sh << 'EOF'
#!/bin/bash

set -euo pipefail

# =========================
# EMAIL SERVER CONFIGURATION
# =========================
DOMAIN=$(hostname -d)
if [ -z "$DOMAIN" ]; then
    echo "❌ Error: Unable to determine domain name."
    echo "Please set your hostname with a proper domain:"
    echo "  hostnamectl set-hostname mail.yourdomain.com"
    exit 1
fi

IP=$(curl -s ifconfig.me)
EMAIL_PASSWORD=$(openssl rand -base64 12)

# =========================
# INSTALL MAIL PACKAGES
# =========================
echo "🔧 Installing mail server packages..."
apt update
apt install -y postfix postfix-mysql dovecot-core dovecot-imapd dovecot-pop3d \
  dovecot-lmtpd dovecot-mysql opendkim opendkim-tools spamassassin spamc \
  clamav clamav-daemon amavisd-new roundcube roundcube-mysql

# =========================
# POSTFIX CONFIGURATION
# =========================
echo "🔧 Configuring Postfix..."

# Backup original config
cp /etc/postfix/main.cf /etc/postfix/main.cf.bak

# Configure main.cf
cat > /etc/postfix/main.cf << EOF
# Basic Settings
smtpd_banner = \$myhostname ESMTP \$mail_name
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 2

# TLS parameters
smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
smtpd_tls_security_level = may
smtpd_tls_loglevel = 1
smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache
smtp_tls_security_level = may

# Mail settings
myhostname = $(hostname -f)
myorigin = \$myhostname
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
inet_interfaces = all
inet_protocols = all
mydestination = \$myhostname, localhost.\$mydomain, localhost, \$mydomain
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
mailbox_size_limit = 0
recipient_delimiter = +
virtual_transport = lmtp:unix:private/dovecot-lmtp

# DKIM
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:localhost:8891
non_smtpd_milters = inet:localhost:8891

# Anti-spam and security
smtpd_recipient_restrictions = 
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination,
    reject_rbl_client zen.spamhaus.org,
    reject_rbl_client bl.spamcop.net
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination
disable_vrfy_command = yes
EOF

# =========================
# DOVECOT CONFIGURATION
# =========================
echo "🔧 Configuring Dovecot..."

# Backup original config
cp /etc/dovecot/dovecot.conf /etc/dovecot/dovecot.conf.bak

# Configure Dovecot
cat > /etc/dovecot/dovecot.conf << EOF
protocols = imap pop3 lmtp
listen = *, ::

mail_location = maildir:/var/mail/vhosts/%d/%n
mail_privileged_group = mail

namespace inbox {
  inbox = yes
}

service auth {
  unix_listener auth-userdb {
    mode = 0600
    user = vmail
    group = mail
  }
  unix_listener /var/spool/postfix/private/auth {
    mode = 0666
    user = postfix
    group = postfix
  }
}

service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}

ssl = required
ssl_cert = </etc/ssl/certs/ssl-cert-snakeoil.pem
ssl_key = </etc/ssl/private/ssl-cert-snakeoil.key
ssl_min_protocol = TLSv1.2
ssl_prefer_server_ciphers = yes
EOF

# =========================
# OPENDKIM CONFIGURATION
# =========================
echo "🔧 Configuring OpenDKIM..."

# Create directory structure
mkdir -p /etc/opendkim/keys/$DOMAIN

# Configure OpenDKIM
cat > /etc/opendkim.conf << EOF
AutoRestart             Yes
AutoRestartRate         10/1h
Syslog                  yes
SyslogSuccess           Yes
LogWhy                  Yes
Canonicalization        relaxed/simple
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable
Mode                    sv
PidFile                 /var/run/opendkim/opendkim.pid
SignatureAlgorithm      rsa-sha256
UserID                  opendkim:opendkim
Socket                  inet:8891@localhost
EOF

# Create files for OpenDKIM
echo "$DOMAIN" > /etc/opendkim/TrustedHosts
echo "127.0.0.1" >> /etc/opendkim/TrustedHosts
echo "localhost" >> /etc/opendkim/TrustedHosts
echo "$IP" >> /etc/opendkim/TrustedHosts

echo "mail._domainkey.$DOMAIN $DOMAIN:mail:/etc/opendkim/keys/$DOMAIN/mail.private" > /etc/opendkim/KeyTable
echo "*@$DOMAIN mail._domainkey.$DOMAIN" > /etc/opendkim/SigningTable

# Generate DKIM keys
cd /etc/opendkim/keys/$DOMAIN
opendkim-genkey -s mail -d $DOMAIN
chown opendkim:opendkim mail.private

# Get the DKIM record
DKIM_RECORD=$(cat mail.txt)
echo "===================="
echo "🔑 DKIM DNS Record:"
echo "$DKIM_RECORD"
echo "===================="

# =========================
# SPAM AND VIRUS CONFIGURATION
# =========================
echo "🔧 Configuring SpamAssassin and ClamAV..."

# Configure SpamAssassin
sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/spamassassin
sed -i 's/CRON=0/CRON=1/' /etc/default/spamassassin

# Update virus database
systemctl stop clamav-freshclam
freshclam
systemctl start clamav-freshclam

# =========================
# CREATE MAIL DIRECTORIES
# =========================
echo "🔧 Creating mail directories..."

# Create vmail user for mail delivery
if ! id -u vmail &>/dev/null; then
  useradd -r -u 150 -g mail -d /var/mail/vhosts -c "Virtual Mail User" vmail
fi

# Create mail directories
mkdir -p /var/mail/vhosts/$DOMAIN
chown -R vmail:mail /var/mail/vhosts

# =========================
# DNS RECORDS TO ADD
# =========================
echo "===================="
echo "🌐 Add these DNS records for your domain ($DOMAIN):"
echo ""
echo "SPF Record (TXT record for @):"
echo "v=spf1 ip4:$IP ~all"
echo ""
echo "DKIM Record (TXT record for mail._domainkey):"
echo "$DKIM_RECORD"
echo ""
echo "DMARC Record (TXT record for _dmarc):"
echo "v=DMARC1; p=quarantine; sp=quarantine; adkim=r; aspf=r; rua=mailto:admin@$DOMAIN; ruf=mailto:admin@$DOMAIN; fo=1; pct=100;"
echo "===================="

# =========================
# RESTART SERVICES
# =========================
systemctl restart postfix dovecot opendkim spamassassin

# =========================
# CREATE TEST USER
# =========================
echo "🔧 Creating test email account..."

# Create test email directory
mkdir -p /var/mail/vhosts/$DOMAIN/admin
chown -R vmail:mail /var/mail/vhosts/$DOMAIN

# Add user to Dovecot passwd file
echo "admin@$DOMAIN:{PLAIN}$EMAIL_PASSWORD:150:150::/var/mail/vhosts/$DOMAIN/admin::" > /etc/dovecot/users

# =========================
# COMPLETE
# =========================
echo "✅ Email server configuration complete"
echo "📧 Test email account created:"
echo "   Username: admin@$DOMAIN"
echo "   Password: $EMAIL_PASSWORD"
echo "   Web access: http://$(hostname -f)/roundcube/"
echo ""
echo "⚠️ IMPORTANT: Add the DNS records shown above to your DNS configuration"
echo "   Test your email setup with: https://mail-tester.com" 
EOF
    chmod +x /opt/aapanel/postfix-config.sh
  fi
  
  # Run the postfix configuration script
  bash /opt/aapanel/postfix-config.sh
  echo -e "${GREEN}✅ Mail server setup completed${NC}"
else
  echo -e "${YELLOW}Mail server setup skipped${NC}"
fi

# =========================
# RUN ADDITIONAL SCRIPTS
# =========================
echo -e "${BLUE}🔧 Running additional configuration scripts...${NC}"

# Run security hardening script
echo -e "${YELLOW}Running security hardening script...${NC}"
bash /opt/aapanel/security-hardening.sh
echo -e "${GREEN}✅ Security hardening completed${NC}"

# Setting up monitoring
echo -e "${YELLOW}Setting up monitoring...${NC}"
if [ ! -f "/opt/aapanel/monitoring.sh" ]; then
  cat > /opt/aapanel/monitoring.sh << 'EOF'
#!/bin/bash

set -euo pipefail

# =========================
# MONITORING SETUP
# =========================
NETDATA_INSTALL_URL="https://my-netdata.io/kickstart.sh"
TELEGRAM_BOT_TOKEN=${1:-""}
TELEGRAM_CHAT_ID=${2:-""}

# =========================
# NETDATA INSTALLATION
# =========================
echo "🔧 Installing Netdata monitoring..."
if [ ! -d "/opt/netdata" ] && [ ! -d "/usr/libexec/netdata" ]; then
  bash <(curl -Ss $NETDATA_INSTALL_URL) --dont-wait --stable-channel --disable-telemetry
  
  # Configure Netdata retention (7 days)
  if [ -f "/etc/netdata/netdata.conf" ]; then
    sed -i 's/# history = 3996/history = 10080/g' /etc/netdata/netdata.conf
  fi
else
  echo "  ✅ Netdata already installed."
fi

# =========================
# HEALTH CHECK SCRIPT
# =========================
echo "🔧 Creating health check script..."

cat > /opt/aapanel/health-check.sh << 'EOL'
#!/bin/bash

# Health check script for aaPanel server
# Checks critical services and sends alerts

# Configuration
LOG_FILE="/var/log/health-check.log"
ERROR_COUNT=0
TELEGRAM_BOT_TOKEN="BOT_TOKEN_HERE"
TELEGRAM_CHAT_ID="CHAT_ID_HERE"

# Create log file if it doesn't exist
touch $LOG_FILE

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

send_alert() {
  if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
    log "Sending Telegram alert: $1"
    curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
         -d chat_id="$TELEGRAM_CHAT_ID" \
         -d text="🚨 Server Alert ($HOSTNAME): $1" \
         -d parse_mode="Markdown" > /dev/null
  else
    log "Alert (no Telegram configured): $1"
    # Send email alert as fallback
    echo "$1" | mail -s "🚨 Server Alert: $HOSTNAME" root@localhost
  fi
}

# Check system load
check_load() {
  log "Checking system load..."
  LOAD=$(cat /proc/loadavg | awk '{print $1}')
  CORES=$(nproc)
  THRESHOLD=$(echo "$CORES * 1.5" | bc)
  
  if (( $(echo "$LOAD > $THRESHOLD" | bc -l) )); then
    send_alert "High system load: $LOAD (threshold: $THRESHOLD)"
    ERROR_COUNT=$((ERROR_COUNT + 1))
  fi
}

# Check disk space
check_disk() {
  log "Checking disk space..."
  DISK_USAGE=$(df -h / | grep -v Filesystem | awk '{print $5}' | tr -d '%')
  
  if [ "$DISK_USAGE" -gt 85 ]; then
    send_alert "Low disk space: ${DISK_USAGE}% used on root filesystem"
    ERROR_COUNT=$((ERROR_COUNT + 1))
  fi
  
  # Check /mnt/data if it exists
  if [ -d "/mnt/data" ]; then
    DATA_USAGE=$(df -h /mnt/data | grep -v Filesystem | awk '{print $5}' | tr -d '%')
    if [ "$DATA_USAGE" -gt 85 ]; then
      send_alert "Low disk space: ${DATA_USAGE}% used on /mnt/data"
      ERROR_COUNT=$((ERROR_COUNT + 1))
    fi
  fi
}

# Check aaPanel service
check_aapanel() {
  log "Checking aaPanel service..."
  if ! curl -s --head --fail http://localhost:2086 >/dev/null; then
    send_alert "aaPanel is not responding on port 2086"
    ERROR_COUNT=$((ERROR_COUNT + 1))
  fi
}

# Check Nginx/Apache service
check_web() {
  log "Checking web server..."
  
  # Check if Nginx is installed and expected to be running
  if systemctl list-unit-files | grep -q nginx; then
    if ! systemctl is-active --quiet nginx; then
      send_alert "Nginx service is not running"
      ERROR_COUNT=$((ERROR_COUNT + 1))
    fi
  fi
  
  # Check if Apache is installed and expected to be running
  if systemctl list-unit-files | grep -q apache2; then
    if ! systemctl is-active --quiet apache2; then
      send_alert "Apache service is not running"
      ERROR_COUNT=$((ERROR_COUNT + 1))
    fi
  fi
}

# Check database services
check_databases() {
  log "Checking database services..."
  
  # Check MySQL/MariaDB
  if systemctl list-unit-files | grep -q -E 'mysql|mariadb'; then
    if ! systemctl is-active --quiet mysql && ! systemctl is-active --quiet mariadb; then
      send_alert "MySQL/MariaDB service is not running"
      ERROR_COUNT=$((ERROR_COUNT + 1))
    fi
  fi
  
  # Check PostgreSQL
  if systemctl list-unit-files | grep -q postgresql; then
    if ! systemctl is-active --quiet postgresql; then
      send_alert "PostgreSQL service is not running"
      ERROR_COUNT=$((ERROR_COUNT + 1))
    fi
  fi
  
  # Check MongoDB
  if docker ps --format '{{.Names}}' | grep -q mongodb; then
    if ! docker exec -i $(docker ps -q --filter name=mongodb) mongosh --eval "db.stats()" &>/dev/null; then
      send_alert "MongoDB container is not responding"
      ERROR_COUNT=$((ERROR_COUNT + 1))
    fi
  fi
}

# Check mail services
check_mail() {
  log "Checking mail services..."
  
  # Check Postfix
  if systemctl list-unit-files | grep -q postfix; then
    if ! systemctl is-active --quiet postfix; then
      send_alert "Postfix service is not running"
      ERROR_COUNT=$((ERROR_COUNT + 1))
    fi
  fi
  
  # Check Dovecot
  if systemctl list-unit-files | grep -q dovecot; then
    if ! systemctl is-active --quiet dovecot; then
      send_alert "Dovecot service is not running"
      ERROR_COUNT=$((ERROR_COUNT + 1))
    fi
  fi
}

# Check for failed backups
check_backups() {
  log "Checking backup status..."
  if [ -f "/var/log/backup-aapanel.log" ]; then
    if grep -i "error\|failed\|fail" /var/log/backup-aapanel.log | grep -q "$(date +%Y-%m-%d)"; then
      send_alert "Backup errors detected in today's backup log"
      ERROR_COUNT=$((ERROR_COUNT + 1))
    fi
  fi
}

# Check for security issues
check_security() {
  log "Checking security..."
  
  # Check for failed SSH attempts
  FAILED_SSH=$(grep -i "Failed password" /var/log/auth.log | grep "$(date +%Y-%m-%d)" | wc -l)
  if [ "$FAILED_SSH" -gt 20 ]; then
    send_alert "High number of failed SSH login attempts: $FAILED_SSH"
    ERROR_COUNT=$((ERROR_COUNT + 1))
  fi
  
  # Check for banned IPs
  if command -v fail2ban-client &> /dev/null; then
    BANNED_IPS=$(fail2ban-client status | grep "Jail list" | sed 's/^.*Jail list:\s*//' | tr ',' ' ' | wc -w)
    if [ "$BANNED_IPS" -gt 10 ]; then
      send_alert "High number of banned IPs: $BANNED_IPS"
      ERROR_COUNT=$((ERROR_COUNT + 1))
    fi
  fi
}

# Run all checks
echo "==========================" >> $LOG_FILE
log "Starting health check"
check_load
check_disk
check_aapanel
check_web
check_databases
check_mail
check_backups
check_security

# Summary
if [ "$ERROR_COUNT" -eq 0 ]; then
  log "Health check completed successfully. No issues found."
else
  log "Health check completed with $ERROR_COUNT errors."
fi
EOL

# Make the script executable
chmod +x /opt/aapanel/health-check.sh

# Replace placeholders with actual values if provided
if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
  sed -i "s/BOT_TOKEN_HERE/$TELEGRAM_BOT_TOKEN/g" /opt/aapanel/health-check.sh
  sed -i "s/CHAT_ID_HERE/$TELEGRAM_CHAT_ID/g" /opt/aapanel/health-check.sh
  echo "  ✅ Telegram notifications configured."
else
  echo "  ℹ️ No Telegram credentials provided. Health checks will log locally."
  echo "  ℹ️ To enable Telegram alerts, edit /opt/aapanel/health-check.sh"
fi

# =========================
# SET UP HEALTH CHECK CRON
# =========================
echo "🔧 Setting up health check cron job..."
if ! grep -q "health-check.sh" /etc/crontab; then
  echo "*/15 * * * * root /opt/aapanel/health-check.sh > /dev/null 2>&1" >> /etc/crontab
  echo "  ✅ Health check cron job added."
else
  echo "  ✅ Health check cron job already exists."
fi

# =========================
# CONFIGURE LOGROTATE
# =========================
echo "🔧 Configuring log rotation..."
cat > /etc/logrotate.d/aapanel << 'EOF'
/var/log/backup-aapanel.log
/var/log/health-check.log
{
    rotate 14
    daily
    missingok
    notifempty
    compress
    delaycompress
    create 0640 root root
    sharedscripts
    postrotate
        systemctl reload rsyslog >/dev/null 2>&1 || true
    endscript
}

/www/wwwlogs/*.log
{
    rotate 14
    daily
    missingok
    notifempty
    compress
    delaycompress
    create 0640 www-data www-data
    sharedscripts
    postrotate
        systemctl reload nginx >/dev/null 2>&1 || true
        systemctl reload apache2 >/dev/null 2>&1 || true
    endscript
}

/www/server/panel/logs/request/*.log
{
    rotate 7
    daily
    missingok
    notifempty
    compress
    delaycompress
    create 0640 root root
    sharedscripts
    postrotate
        bt restart panel >/dev/null 2>&1 || true
    endscript
}
EOF
echo "  ✅ Log rotation configured."
EOF
chmod +x /opt/aapanel/monitoring.sh
fi

# Run the monitoring script
bash /opt/aapanel/monitoring.sh
echo -e "${GREEN}✅ Monitoring setup completed${NC}"

# =========================
# ADDITIONAL SECURITY ADVICE
# =========================
echo -e "${BLUE}🔒 Additional security recommendation:${NC}"
echo -e "${YELLOW}It's recommended to create a non-root user for daily administration:${NC}"
echo -e "Run the following commands after setup:"
echo -e "  adduser admin"
echo -e "  usermod -aG sudo admin"
echo -e "  # After testing sudo access, disable root SSH login:"
echo -e "  sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin no/g' /etc/ssh/sshd_config"
echo -e "  systemctl restart sshd"

# =========================
# WORDPRESS ONE-CLICK SETUP
# =========================
echo -e "${BLUE}🔧 Setting up WordPress one-click script...${NC}"
cat > /opt/aapanel/wordpress-setup.sh << 'EOF'
#!/bin/bash

set -euo pipefail

# WordPress Quick Setup Script for aaPanel
DOMAIN=$1
DB_NAME=${2:-"wp_$(date +%s | sha256sum | base64 | head -c 8)"}
DB_USER=${3:-"wpuser_$(date +%s | sha256sum | base64 | head -c 8)"}
DB_PASS=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9')

if [ -z "$DOMAIN" ]; then
  echo "Usage: $0 domain.com [db_name] [db_user]"
  exit 1
fi

# Check if domain directory exists
SITE_DIR="/mnt/data/wwwroot/$DOMAIN"
if [ -d "$SITE_DIR" ]; then
  echo "⚠️ Warning: Site directory already exists at $SITE_DIR"
  read -p "Continue and replace existing files? (y/n): " CONTINUE
  if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
  fi
fi

# Create website directory
echo "📁 Creating website directory..."
mkdir -p $SITE_DIR
cd $SITE_DIR

# Download WordPress
echo "📥 Downloading WordPress..."
wget https://wordpress.org/latest.tar.gz
tar -xzf latest.tar.gz
cp -rf wordpress/* .
rm -rf wordpress latest.tar.gz

# Create wp-config.php
echo "🔧 Configuring WordPress..."
cp wp-config-sample.php wp-config.php

# Generate salts
SALTS=$(curl -s https://api.wordpress.org/secret-key/1.1/salt/)
sed -i "/AUTH_KEY/,/NONCE_SALT/c\\$SALTS" wp-config.php

# Set database details
sed -i "s/database_name_here/$DB_NAME/" wp-config.php
sed -i "s/username_here/$DB_USER/" wp-config.php
sed -i "s/password_here/$DB_PASS/" wp-config.php

# Check for MySQL and create database if available
if command -v mysql &> /dev/null; then
  # Get MySQL credentials from the panel
  if [ -f "/www/server/panel/config/config.json" ]; then
    MYSQL_ROOT=$(grep -o '"mysql_root":[^,}]*' /www/server/panel/config/config.json | cut -d'"' -f4)
    MYSQL_PASS=$(grep -o '"mysql_root_pwd":[^,}]*' /www/server/panel/config/config.json | cut -d'"' -f4)
    
    if [ -n "$MYSQL_ROOT" ] && [ -n "$MYSQL_PASS" ]; then
      echo "🗄️ Creating MySQL database..."
      mysql -u$MYSQL_ROOT -p$MYSQL_PASS -e "CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
      mysql -u$MYSQL_ROOT -p$MYSQL_PASS -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';"
      mysql -u$MYSQL_ROOT -p$MYSQL_PASS -e "FLUSH PRIVILEGES;"
      echo "✅ Database created successfully."
    else
      echo "⚠️ MySQL credentials not found in aaPanel config."
    fi
  else
    echo "⚠️ aaPanel MySQL configuration not found."
  fi
else
  echo "⚠️ MySQL not installed. You'll need to create the database manually."
fi

# Set permissions
echo "🔒 Setting permissions..."
find . -type d -exec chmod 755 {} \;
find . -type f -exec chmod 644 {} \;
chown -R www-data:www-data .

# Create .htaccess with permalinks
cat > .htaccess << EOL
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
EOL

echo "===================="
echo "✅ WordPress installation complete!"
echo "📋 Installation details:"
echo "  Domain: $DOMAIN"
echo "  Site directory: $SITE_DIR"
echo "  Database name: $DB_NAME"
echo "  Database user: $DB_USER"
echo "  Database password: $DB_PASS"
echo "===================="
echo "⚠️ Next steps:"
echo "1. Create website in aaPanel and point it to: $SITE_DIR"
echo "2. Set up SSL using Let's Encrypt from the aaPanel"
echo "3. Complete WordPress setup by visiting: https://$DOMAIN"
echo "===================="
EOF

chmod +x /opt/aapanel/wordpress-setup.sh
echo -e "${GREEN}✅ WordPress one-click setup script created${NC}"
echo -e "Usage: bash /opt/aapanel/wordpress-setup.sh yourdomain.com"

# =========================
# WRAP UP
# =========================
echo -e "${BLUE}==========================${NC}"
echo -e "${GREEN}✅ aaPanel Setup Complete!${NC}"
echo -e "${BLUE}==========================${NC}"
echo -e "Access aaPanel at: http://$(hostname -I | awk '{print $1}'):$AA_PANEL_PORT"
echo -e "Netdata dashboard: http://$(hostname -I | awk '{print $1}'):19999"
echo -e ""
echo -e "${YELLOW}Important files and directories:${NC}"
echo -e "  Web root: $WEB_DIR"
echo -e "  MongoDB data: $MONGO_DIR"
echo -e "  PostgreSQL data: $POSTGRES_DIR"
echo -e "  Backups: $BACKUP_DIR"
echo -e "  Configuration scripts: /opt/aapanel/"
echo -e ""
echo -e "${YELLOW}Database credentials:${NC}"
echo -e "  MongoDB: admin / $DB_PASSWORD"
echo -e "  Redis password: $REDIS_PASSWORD"
if [ -n "${PG_PASSWORD:-}" ]; then
  echo -e "  PostgreSQL: postgres / $PG_PASSWORD"
fi
echo -e ""
echo -e "${YELLOW}Available scripts:${NC}"
echo -e "  WordPress setup: /opt/aapanel/wordpress-setup.sh yourdomain.com"
echo -e "  Docker management: /opt/aapanel/docker-manager.sh [service] [action]"
echo -e "  Manual backup: /opt/aapanel/backup.sh"
echo -e ""
echo -e "${YELLOW}Next steps:${NC}"
echo -e "1. Access the aaPanel and change the default password"
echo -e "2. Install additional software through the panel (MySQL, PostgreSQL, etc.)"
echo -e "3. Configure rclone for remote backups: rclone config"
echo -e "4. Create a non-root user for administration"
echo -e "5. Check all services are running properly with: netdata dashboard"
echo -e "6. Set up websites with WordPress or other applications"
echo -e ""
echo -e "Setup completed at $(date)"
echo -e "${BLUE}==========================${NC}"
