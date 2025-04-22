# aaPanel Server Deployment

This repository contains scripts for a complete server setup using aaPanel (Free) with enhanced security, monitoring, backups, and essential services.

## 📋 Components

### 📦 Base Server
- Ubuntu 22.04 LTS
- Root user configured
- 2GB Swap enabled

### 🧱 aaPanel Installation
- Custom port (2086)
- Let's Encrypt SSL for panel
- Firewall protection

### 🔐 Security
- Fail2Ban protection
- ModSecurity + OWASP CRS
- UFW firewall with essential ports only
- Security hardening

### 🗄️ Databases
- MySQL/MariaDB (via panel)
- PostgreSQL (via plugin)
- MongoDB (via Docker)
- Redis (via Docker)

### 📬 Email Server (Optional)
- Postfix + Dovecot + Roundcube
- SPF, DKIM, DMARC configured
- SSL for email (STARTTLS and SMTPS)
- Anti-spam protection

### ☁️ Storage & Backup
- Persistent volumes in `/mnt/data/`
- Local backups
- Remote S3 backups with rclone
- Automated backup cron jobs

### 📊 Monitoring
- Netdata real-time monitoring
- Health check scripts
- Telegram/Email alerts
- Log rotation

### 🐳 Docker
- MongoDB and Redis containers
- Auto-restart configuration
- Volume persistence
- Backup integration

## 🛠️ Installation

### Prerequisites
- Fresh Ubuntu 22.04 LTS installation
- Root access
- Public IP address with DNS records set (for SSL)

### Installation Steps

1. Clone this repository:
```bash
git clone https://github.com/yourusername/aapanel-server-setup.git
cd aapanel-server-setup
```

2. Run the setup script:
```bash
chmod +x setup.sh
./setup.sh
```

3. Follow the prompts during installation.

4. After installation, access aaPanel at:
```
http://YOUR_SERVER_IP:2086
```

## 📁 Directory Structure

- `/mnt/data/wwwroot` - Web files
- `/mnt/data/mongodb` - MongoDB data
- `/mnt/data/redis` - Redis data
- `/mnt/data/backups` - Backup files
- `/opt/aapanel/` - Support scripts and configuration

## 🔍 Configuration Files

- `/opt/aapanel/docker-compose.yaml` - Docker services configuration
- `/opt/aapanel/backup.sh` - Backup script
- `/opt/aapanel/security-hardening.sh` - Security settings
- `/opt/aapanel/postfix-config.sh` - Email server configuration
- `/opt/aapanel/monitoring.sh` - Monitoring setup
- `/opt/aapanel/rclone.conf.example` - Rclone configuration example

## ⚙️ Post-Installation

1. Change the default aaPanel password
2. Install desired software through the panel (MySQL, PHP, etc.)
3. Configure rclone for remote backups using:
```bash
rclone config
```
4. Create a non-root user for administration:
```bash
adduser admin
usermod -aG sudo admin
```
5. After testing sudo access, disable root SSH login:
```bash
sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin no/g' /etc/ssh/sshd_config
systemctl restart sshd
```

## 📊 Monitoring

- Netdata dashboard: `http://YOUR_SERVER_IP:19999`
- Health checks run every 15 minutes
- Logs available at `/var/log/health-check.log`
- Backup logs at `/var/log/backup-aapanel.log`

## 🔄 Backups

Backups run daily at 2 AM and include:
- MySQL/PostgreSQL databases
- MongoDB databases
- Web files
- Panel configuration
- Email data

Backups are stored in `/mnt/data/backups` and synced to configured S3 storage.

## 📧 Email Testing

After setting up the email server, test your configuration with:
- https://mail-tester.com
- https://mxtoolbox.com

## 🆘 Troubleshooting

If you encounter issues:

1. Check logs in `/var/log/aapanel-setup.log`
2. View aaPanel logs in `/www/server/panel/logs/`
3. Check Netdata for resource issues
4. Review service status with `systemctl status [service-name]`

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details. 