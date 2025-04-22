#!/bin/bash

# =========================
# ANSI COLOR CODES
# =========================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}❌ This script must be run as root${NC}"
    exit 1
fi

echo -e "${BLUE}==========================${NC}"
echo -e "${BLUE}aaPanel Setup Verification${NC}"
echo -e "${BLUE}==========================${NC}"

# Test variables
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

# Function to check status
check_status() {
    local service=$1
    local check_command=$2
    local error_message=$3
    
    echo -ne "Checking ${service}... "
    
    if eval "$check_command"; then
        echo -e "${GREEN}✅ PASS${NC}"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo -e "${RED}❌ FAIL${NC}"
        echo -e "   ${RED}$error_message${NC}"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

# Function to check status with warning possibility
check_status_warn() {
    local service=$1
    local pass_command=$2
    local warn_command=$3
    local pass_message=$4
    local warn_message=$5
    local fail_message=$6
    
    echo -ne "Checking ${service}... "
    
    if eval "$pass_command"; then
        echo -e "${GREEN}✅ PASS${NC}"
        echo -e "   ${GREEN}$pass_message${NC}"
        PASS_COUNT=$((PASS_COUNT + 1))
    elif eval "$warn_command"; then
        echo -e "${YELLOW}⚠️ WARNING${NC}"
        echo -e "   ${YELLOW}$warn_message${NC}"
        WARN_COUNT=$((WARN_COUNT + 1))
    else
        echo -e "${RED}❌ FAIL${NC}"
        echo -e "   ${RED}$fail_message${NC}"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

echo -e "\n${BLUE}🖥️ System Information:${NC}"
echo "Hostname: $(hostname)"
echo "IP Address: $(hostname -I | awk '{print $1}')"
echo "OS: $(lsb_release -ds)"
echo "Kernel: $(uname -r)"
echo "Memory: $(free -h | grep Mem | awk '{print $2}')"
echo "Swap: $(free -h | grep Swap | awk '{print $2}')"
echo "Disk Space: $(df -h / | grep -v Filesystem | awk '{print $2}')"

echo -e "\n${BLUE}🔍 Checking Core Services:${NC}"

# Check aaPanel
check_status "aaPanel service" "test -d /www/server/panel" "aaPanel is not installed at /www/server/panel"
check_status "aaPanel port" "grep -q '[0-9]\\+' /www/server/panel/data/port.pl" "aaPanel port is not configured"
AA_PORT=$(cat /www/server/panel/data/port.pl 2>/dev/null || echo "8888")
check_status "aaPanel accessibility" "curl -s --head --fail http://localhost:$AA_PORT >/dev/null" "aaPanel is not responding on port $AA_PORT"

# Check Docker
check_status "Docker installation" "command -v docker >/dev/null" "Docker is not installed"
check_status "Docker service" "systemctl is-active --quiet docker" "Docker service is not running"
check_status "Docker compose" "command -v docker-compose >/dev/null" "Docker Compose is not installed"
check_status "Docker network" "docker network ls | grep -q aapanel-net" "Docker aapanel-net network is not created"

# Check MongoDB container
check_status_warn "MongoDB container" \
    "docker ps | grep -q aapanel-mongodb" \
    "docker ps -a | grep -q aapanel-mongodb" \
    "MongoDB container is running" \
    "MongoDB container exists but is not running" \
    "MongoDB container is not created"

# Check Redis container
check_status_warn "Redis container" \
    "docker ps | grep -q aapanel-redis" \
    "docker ps -a | grep -q aapanel-redis" \
    "Redis container is running" \
    "Redis container exists but is not running" \
    "Redis container is not created"

# Check directory structure
echo -e "\n${BLUE}📁 Checking Directory Structure:${NC}"
check_status "Web directory" "test -d /mnt/data/wwwroot" "Web directory /mnt/data/wwwroot does not exist"
check_status "MongoDB directory" "test -d /mnt/data/mongodb" "MongoDB directory /mnt/data/mongodb does not exist"
check_status "Backup directory" "test -d /mnt/data/backups" "Backup directory /mnt/data/backups does not exist"
check_status "Script directory" "test -d /opt/aapanel" "Script directory /opt/aapanel does not exist"

# Check security
echo -e "\n${BLUE}🔒 Checking Security Configuration:${NC}"
check_status "UFW" "ufw status | grep -q 'Status: active'" "UFW firewall is not active"
check_status "Fail2Ban" "systemctl is-active --quiet fail2ban" "Fail2Ban service is not running"
check_status "SSH hardening" "grep -q 'Protocol 2' /etc/ssh/sshd_config" "SSH hardening may not be configured properly"

# Check cron jobs
echo -e "\n${BLUE}⏱️ Checking Scheduled Tasks:${NC}"
check_status "Backup cron job" "grep -q backup-aapanel /etc/crontab" "Backup cron job is not configured"

# Check monitoring
echo -e "\n${BLUE}📊 Checking Monitoring:${NC}"
check_status_warn "Netdata" \
    "systemctl is-active --quiet netdata" \
    "test -d /opt/netdata -o -d /usr/libexec/netdata" \
    "Netdata service is running" \
    "Netdata is installed but may not be running" \
    "Netdata may not be installed"

check_status "Health check script" "test -f /opt/aapanel/health-check.sh && test -x /opt/aapanel/health-check.sh" "Health check script is missing or not executable"

# Check backup
echo -e "\n${BLUE}💾 Checking Backup Configuration:${NC}"
check_status "Backup script" "test -f /opt/aapanel/backup.sh && test -x /opt/aapanel/backup.sh" "Backup script is missing or not executable"
check_status_warn "Rclone config" \
    "rclone listremotes 2>/dev/null | grep -q :" \
    "command -v rclone >/dev/null" \
    "Rclone is configured with remotes" \
    "Rclone is installed but may not be configured" \
    "Rclone may not be installed"

# Check Mail (optional)
echo -e "\n${BLUE}📧 Checking Mail Configuration (Optional):${NC}"
check_status_warn "Mail server" \
    "systemctl is-active --quiet postfix && systemctl is-active --quiet dovecot" \
    "systemctl is-active --quiet postfix || systemctl is-active --quiet dovecot" \
    "Mail services (Postfix & Dovecot) are running" \
    "Some mail services are running, but not all" \
    "Mail services may not be installed"

# Summary
echo -e "\n${BLUE}==========================${NC}"
echo -e "${BLUE}Verification Summary${NC}"
echo -e "${BLUE}==========================${NC}"
echo -e "${GREEN}✅ Passed: $PASS_COUNT checks${NC}"
if [ "$WARN_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}⚠️ Warnings: $WARN_COUNT checks${NC}"
fi
if [ "$FAIL_COUNT" -gt 0 ]; then
    echo -e "${RED}❌ Failed: $FAIL_COUNT checks${NC}"
fi

echo -e "\n${BLUE}Recommendation:${NC}"
if [ "$FAIL_COUNT" -eq 0 ] && [ "$WARN_COUNT" -eq 0 ]; then
    echo -e "${GREEN}✅ All checks passed! Your system is properly configured.${NC}"
elif [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "${YELLOW}⚠️ System is functional with some warnings. Review the warnings above.${NC}"
else
    echo -e "${RED}❌ Some checks failed. Please fix the issues highlighted above.${NC}"
    echo -e "${YELLOW}You may need to run the setup script again or manually fix the failed components.${NC}"
fi

echo -e "\n${BLUE}==========================${NC}" 