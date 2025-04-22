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

cat > /opt/aapanel/health-check.sh << 'EOF'
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
EOF

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
# LOGROTATE CONFIGURATION
# =========================
echo "🔧 Setting up log rotation..."

# Configure logrotate for health check logs
cat > /etc/logrotate.d/health-check << EOF
/var/log/health-check.log {
  weekly
  rotate 12
  compress
  delaycompress
  missingok
  notifempty
  create 644 root root
}
EOF

# Configure logrotate for backup logs
cat > /etc/logrotate.d/backup << EOF
/var/log/backup-aapanel.log {
  weekly
  rotate 12
  compress
  delaycompress
  missingok
  notifempty
  create 644 root root
}
EOF

echo "✅ Monitoring setup complete!"
echo "   - Netdata dashboard: http://$(hostname -I | awk '{print $1}'):19999"
echo "   - Health checks run every 15 minutes"
echo "   - View health check logs at: /var/log/health-check.log" 