#!/bin/bash

set -euo pipefail

# =========================
# SECURITY HARDENING SCRIPT
# =========================
echo "🔒 Starting security hardening process..."

# =========================
# FIREWALL CONFIGURATION
# =========================
echo "🔧 Configuring firewall (UFW)..."

# Reset UFW to default
ufw --force reset

# Set default policies
ufw default deny incoming
ufw default allow outgoing

# Allow essential services
ufw allow ssh
ufw allow 2086/tcp  # aaPanel port
ufw allow http
ufw allow https
ufw allow 25/tcp    # SMTP
ufw allow 465/tcp   # SMTPS
ufw allow 587/tcp   # Submission
ufw allow 110/tcp   # POP3
ufw allow 995/tcp   # POP3S
ufw allow 143/tcp   # IMAP
ufw allow 993/tcp   # IMAPS
ufw allow 3306/tcp  # MySQL (optional - consider limiting to localhost)

# Enable UFW
ufw --force enable

# =========================
# FAIL2BAN CONFIGURATION
# =========================
echo "🔧 Configuring Fail2Ban..."

# Install fail2ban if not already installed
apt install -y fail2ban

# Create custom configuration
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# Ban hosts for 1 hour
bantime = 3600
# Check for 10 minutes
findtime = 600
# Ban after 5 attempts
maxretry = 5
# Email notification
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
port = 2086
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
EOF

# Create custom filter for aaPanel
cat > /etc/fail2ban/filter.d/aapanel.conf << EOF
[Definition]
failregex = ^.* ((Username|Unauthorized|Invalid)), ip: <HOST>.*$
ignoreregex =
EOF

# Enable and restart fail2ban
systemctl enable fail2ban
systemctl restart fail2ban

# =========================
# SSH HARDENING
# =========================
echo "🔧 Hardening SSH configuration..."

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

# Allow only specific users (optional, uncomment and modify as needed)
# AllowUsers admin
EOF

# Restart SSH (careful, this might disconnect your session)
echo "⚠️ SSH will restart in 5 seconds. This may disconnect your current session."
sleep 5
systemctl restart sshd

# =========================
# SETUP AUTOMATED SECURITY UPDATES
# =========================
echo "🔧 Setting up unattended security updates..."

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
# SETUP MODSECURITY WITH NGINX
# =========================
echo "🔧 Setting up ModSecurity with OWASP CRS..."

# Install dependencies
apt install -y libmodsecurity3 libapache2-mod-security2 nginx-module-security

# Clone OWASP Core Rule Set
git clone https://github.com/coreruleset/coreruleset.git /etc/nginx/modsec-crs
cd /etc/nginx/modsec-crs
cp crs-setup.conf.example crs-setup.conf

# Configure ModSecurity
mkdir -p /etc/nginx/modsec
cat > /etc/nginx/modsec/modsecurity.conf << EOF
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
cat > /etc/nginx/modsec/main.conf << EOF
Include "/etc/nginx/modsec/modsecurity.conf"
Include "/etc/nginx/modsec-crs/crs-setup.conf"
Include "/etc/nginx/modsec-crs/rules/*.conf"
EOF

# Add ModSecurity to nginx.conf
if ! grep -q "modsecurity on" /etc/nginx/nginx.conf; then
    sed -i '/http {/a \    modsecurity on;\n    modsecurity_rules_file /etc/nginx/modsec/main.conf;' /etc/nginx/nginx.conf
fi

# =========================
# SECURE SHARED MEMORY
# =========================
echo "🔧 Securing shared memory..."

# Add to fstab if not already there
if ! grep -q "/dev/shm" /etc/fstab; then
    echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
fi

# =========================
# HARDEN SYSTEM SETTINGS
# =========================
echo "🔧 Hardening system settings..."

# Configure system-wide security settings
cat > /etc/sysctl.d/99-security.conf << EOF
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Don't send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Disable IPv6 if not needed (optional)
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1
# net.ipv6.conf.lo.disable_ipv6 = 1

# Protect against TCP time-wait assassination
net.ipv4.tcp_rfc1337 = 1

# Increase system file descriptor limit
fs.file-max = 65535

# Allow local port reuse
net.ipv4.tcp_tw_reuse = 1

# Decrease the time default value for tcp_fin_timeout connection
net.ipv4.tcp_fin_timeout = 15
EOF

# Apply sysctl settings
sysctl -p /etc/sysctl.d/99-security.conf

# =========================
# COMPLETE
# =========================
echo "✅ Security hardening process complete!"
echo "⚠️ Important Note: You should create a non-root user for daily administration."
echo "   To do so, run the following commands:"
echo "   adduser admin"
echo "   usermod -aG sudo admin"
echo "   After testing sudo access with this user, consider disabling root SSH access by"
echo "   modifying PermitRootLogin in /etc/ssh/sshd_config to 'no'" 