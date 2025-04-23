#!/bin/bash

set -euo pipefail

# =========================
# BACKUP CONFIGURATION
# =========================
DATE=$(date +%Y-%m-%d_%H-%M-%S)

# Load environment variables from .env if available
ENV_FILE=".env"
if [ -f "$ENV_FILE" ]; then
  echo "Loading environment variables from $ENV_FILE"
  export $(grep -v '^#' $ENV_FILE | xargs)
else
  echo "Error: .env file not found. Please create one."
  exit 1
fi

# Check for required variables
if [ -z "${BACKUP_DIR:-}" ]; then
  echo "Error: BACKUP_DIR not set in .env. Cannot proceed with backup."
  exit 1
fi

if [ -z "${WEB_DIR:-}" ]; then
  echo "Error: WEB_DIR not set in .env. Cannot proceed with backup."
  exit 1
fi

if [ -z "${WASABI_REMOTE_NAME:-}" ]; then
  echo "Error: WASABI_REMOTE_NAME not set in .env. Wasabi backup will be skipped."
fi

if [ -z "${WASABI_BUCKET_NAME:-}" ]; then
  echo "Error: WASABI_BUCKET_NAME not set in .env. Wasabi backup will be skipped."
fi

PANEL_DIR="/www/server/panel"
MAIL_DIR=${MAIL_DIR:-"/var/mail"}
RETENTION_DAYS=${RETENTION_DAYS:-7}

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
      
      # Check if required variables are set
      if [ -z "${POSTGRES_USER:-}" ]; then
        echo "  ⚠️ POSTGRES_USER not set in .env. Skipping PostgreSQL backup."
        continue
      fi
      
      if [ -z "${POSTGRES_PASSWORD:-}" ]; then
        echo "  ⚠️ POSTGRES_PASSWORD not set in .env. Skipping PostgreSQL backup."
        continue
      fi
      
      # Get all databases
      docker exec -i aapanel-postgres psql -U $POSTGRES_USER -c "SELECT datname FROM pg_database WHERE datistemplate = false AND datname != 'postgres';" -t | while read DB; do
        DB=$(echo $DB | tr -d ' ')
        if [ -n "$DB" ]; then
          echo "  - Backing up PostgreSQL DB: $DB"
          docker exec -i aapanel-postgres pg_dump -U $POSTGRES_USER $DB | gzip > "${BACKUP_DIR}/postgres/${DB}_${DATE}.sql.gz"
        fi
      done
    else
      echo "  ⚠️ PostgreSQL credentials not found. Skipping PostgreSQL backups."
    fi
  fi
else
  if docker ps | grep -q aapanel-postgres; then
    echo "  - Using Docker PostgreSQL"
    
    # Check if required variables are set
    if [ -z "${POSTGRES_USER:-}" ]; then
      echo "  ⚠️ POSTGRES_USER not set in .env. Skipping PostgreSQL backup."
    elif [ -z "${POSTGRES_PASSWORD:-}" ]; then
      echo "  ⚠️ POSTGRES_PASSWORD not set in .env. Skipping PostgreSQL backup."
    else
      # Get all databases
      docker exec -i aapanel-postgres psql -U $POSTGRES_USER -c "SELECT datname FROM pg_database WHERE datistemplate = false AND datname != 'postgres';" -t | while read DB; do
        DB=$(echo $DB | tr -d ' ')
        if [ -n "$DB" ]; then
          echo "  - Backing up PostgreSQL DB: $DB"
          docker exec -i aapanel-postgres pg_dump -U $POSTGRES_USER $DB | gzip > "${BACKUP_DIR}/postgres/${DB}_${DATE}.sql.gz"
        fi
      done
    fi
  else
    echo "  ⚠️ PostgreSQL not installed. Skipping PostgreSQL backups."
  fi
fi

# =========================
# MONGODB BACKUPS
# =========================
if command -v mongodump &> /dev/null && docker ps | grep -q aapanel-mongodb; then
  echo "Backing up MongoDB databases..."
  
  # Check if required variables are set
  if [ -z "${MONGODB_USER:-}" ]; then
    echo "  ⚠️ MONGODB_USER not set in .env. Skipping MongoDB backup."
  elif [ -z "${MONGODB_PASSWORD:-}" ]; then
    echo "  ⚠️ MONGODB_PASSWORD not set in .env. Skipping MongoDB backup."
  else
    MONGO_DUMP_DIR="${BACKUP_DIR}/mongodb/dump_${DATE}"
    mkdir -p "$MONGO_DUMP_DIR"
    
    # Using mongodump to backup all databases
    mongodump --host localhost --port 27017 --username $MONGODB_USER --password $MONGODB_PASSWORD --authenticationDatabase admin --out $MONGO_DUMP_DIR
    
    # Compress the dump
    cd "${BACKUP_DIR}/mongodb"
    tar -czf "mongodb_${DATE}.tar.gz" "dump_${DATE}"
    rm -rf "dump_${DATE}"
    
    echo "  ✅ MongoDB backup completed"
  fi
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
# WASABI CLOUD SYNC
# =========================
echo "Syncing backups to Wasabi Cloud Storage..."
if command -v rclone &> /dev/null && rclone listremotes | grep -q "${WASABI_REMOTE_NAME}:"; then
  rclone sync "${BACKUP_DIR}" "${WASABI_REMOTE_NAME}:${WASABI_BUCKET_NAME}/${HOSTNAME}" \
    --progress --stats-one-line --stats 15s
  echo "  ✅ Wasabi Cloud sync completed"
else
  echo "  ⚠️ Rclone not configured with ${WASABI_REMOTE_NAME} remote. Skipping Wasabi Cloud sync."
  echo "      Configure with: rclone config"
  echo "      Use the Wasabi provider with endpoint s3.${WASABI_REGION:-eu-central-1}.wasabisys.com"
fi

# =========================
# CLEANUP OLD BACKUPS
# =========================
echo "Cleaning up old backups (older than ${RETENTION_DAYS} days)..."
find "${BACKUP_DIR}" -type f -mtime +${RETENTION_DAYS} -name "*.gz" -delete
find "${BACKUP_DIR}" -type f -mtime +${RETENTION_DAYS} -name "*.sql.gz" -delete

echo "Backup completed at $(date)" 