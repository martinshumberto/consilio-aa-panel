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
    echo "  ⚠️ PostgreSQL credentials not found. Skipping PostgreSQL backups."
  fi
else
  echo "  ⚠️ PostgreSQL not installed. Skipping PostgreSQL backups."
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