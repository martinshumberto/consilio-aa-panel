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
useradd -m -s /bin/false admin@$DOMAIN
echo "admin@$DOMAIN:$EMAIL_PASSWORD" | chpasswd

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