#!/bin/bash

set -euo pipefail

# =========================
# MONITORING SETUP
# =========================
# Verify parameters or load from environment
NETDATA_INSTALL_URL="https://my-netdata.io/kickstart.sh"

# If parameters are provided, use them
if [ "$#" -ge 1 ]; then
  DISCORD_WEBHOOK_URL="$1"
else
  # Otherwise, check environment
  if [ -z "${DISCORD_WEBHOOK_URL:-}" ]; then
    DISCORD_WEBHOOK_URL=""
    echo "Warning: No Discord webhook URL provided. Alerts will be disabled."
  fi
fi

if [ "$#" -ge 2 ]; then
  DISCORD_ALERT_USERNAME="$2"
else
  # Check environment
  if [ -z "${DISCORD_ALERT_USERNAME:-}" ]; then
    echo "Error: DISCORD_ALERT_USERNAME not provided as parameter or environment variable."
    exit 1
  fi
fi

if [ "$#" -ge 3 ]; then
  PANEL_DOMAIN="$3"
else
  # Check environment
  if [ -z "${PANEL_DOMAIN:-}" ]; then
    echo "Error: PANEL_DOMAIN not provided as parameter or environment variable."
    exit 1
  fi
fi

if [ "$#" -ge 4 ]; then
  NETDATA_DOMAIN="$4"
else
  # Check environment
  if [ -z "${NETDATA_DOMAIN:-}" ]; then
    echo "Error: NETDATA_DOMAIN not provided as parameter or environment variable."
    exit 1
  fi
fi

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
DISCORD_WEBHOOK_URL="WEBHOOK_URL_HERE"
DISCORD_ALERT_USERNAME="ALERT_USERNAME_HERE"
PANEL_DOMAIN="PANEL_DOMAIN_HERE"

# Create log file if it doesn't exist
touch $LOG_FILE

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

send_alert() {
  if [ -n "$DISCORD_WEBHOOK_URL" ]; then
    log "Sending Discord alert: $1"
    
    # Format timestamp for Discord message
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
    
    # Create JSON payload for Discord webhook
    PAYLOAD=$(cat <<JSON
{
  "username": "$DISCORD_ALERT_USERNAME",
  "content": "🚨 **Server Alert** ($PANEL_DOMAIN)",
  "embeds": [{
    "title": "Server Alert",
    "description": "$1",
    "color": 15158332,
    "timestamp": "$TIMESTAMP",
    "footer": {
      "text": "ConsiliAAP Monitoring"
    }
  }]
}
JSON
)
    
    # Send alert to Discord
    curl -s -H "Content-Type: application/json" -d "$PAYLOAD" "$DISCORD_WEBHOOK_URL" > /dev/null
  else
    log "Alert (no Discord configured): $1"
    # Send email alert as fallback
    echo "$1" | mail -s "🚨 Server Alert: $PANEL_DOMAIN" root@localhost
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
if [ -n "$DISCORD_WEBHOOK_URL" ]; then
  sed -i "s|WEBHOOK_URL_HERE|$DISCORD_WEBHOOK_URL|g" /opt/aapanel/health-check.sh
  sed -i "s|ALERT_USERNAME_HERE|$DISCORD_ALERT_USERNAME|g" /opt/aapanel/health-check.sh
  sed -i "s|PANEL_DOMAIN_HERE|$PANEL_DOMAIN|g" /opt/aapanel/health-check.sh
  echo "  ✅ Discord notifications configured."
else
  echo "  ℹ️ No Discord webhook URL provided. Health checks will log locally."
  echo "  ℹ️ To enable Discord alerts, edit /opt/aapanel/health-check.sh or set DISCORD_WEBHOOK_URL in .env"
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
echo "   - Netdata dashboard: https://$NETDATA_DOMAIN"
echo "   - Panel access: https://$PANEL_DOMAIN"
echo "   - Health checks run every 15 minutes"
echo "   - View health check logs at: /var/log/health-check.log"
echo "   - Discord alerts will be sent to the configured webhook URL" 