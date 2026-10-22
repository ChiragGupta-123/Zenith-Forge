#!/usr/bin/env bash
# ==============================================================================
# DevCollab - Safe SQLite WAL Online Backup Script
# Performs non-blocking atomic backup using SQLite's online backup API,
# compresses the output, and optionally uploads to S3 / Cloudflare R2.
# ==============================================================================

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/opt/devcollab/backups}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_BASENAME="devcollab_${TIMESTAMP}.sqlite"
TEMP_CONTAINER_FILE="/data/sqlite/hot_backup_${TIMESTAMP}.sqlite"
TARGET_FILE="${BACKUP_DIR}/${BACKUP_BASENAME}"

mkdir -p "${BACKUP_DIR}"

echo "[$(date)] Starting DevCollab SQLite hot backup..."

# 1. Trigger safe online backup from inside the running backend container
# (Uses better-sqlite3 native backup API to flush WAL frames atomically)
docker exec devcollab-backend node -e "
  const Database = require('better-sqlite3');
  const db = new Database('/data/sqlite/devcollab.sqlite');
  db.backup('${TEMP_CONTAINER_FILE}')
    .then(() => {
      console.log('Atomic SQLite backup completed inside container.');
      process.exit(0);
    })
    .catch(err => {
      console.error('Backup failed:', err);
      process.exit(1);
    });
"

# 2. Extract hot backup file from container volume
docker cp "devcollab-backend:${TEMP_CONTAINER_FILE}" "${TARGET_FILE}"
docker exec devcollab-backend rm -f "${TEMP_CONTAINER_FILE}"

# 3. Compress with maximum gzip compression
gzip -9 "${TARGET_FILE}"
FINAL_ARCHIVE="${TARGET_FILE}.gz"

echo "[$(date)] Backup successfully created: ${FINAL_ARCHIVE} ($(du -h "${FINAL_ARCHIVE}" | cut -f1))"

# 4. Optional: Upload to remote cloud storage if AWS CLI is configured
if command -v aws >/dev/null 2>&1 && [ -n "${S3_BACKUP_BUCKET:-}" ]; then
    echo "[$(date)] Uploading snapshot to ${S3_BACKUP_BUCKET}..."
    aws s3 cp "${FINAL_ARCHIVE}" "${S3_BACKUP_BUCKET}/${BACKUP_BASENAME}.gz"
    echo "[$(date)] Cloud sync completed."
fi

# 5. Clean up local backups older than 14 days
find "${BACKUP_DIR}" -name "devcollab_*.sqlite.gz" -mtime +14 -delete
echo "[$(date)] Backup rotation completed (14 days retention)."
