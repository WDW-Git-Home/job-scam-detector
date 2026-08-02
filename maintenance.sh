#!/bin/bash
# Job Scam Detector v3.1 - Maintenance Script
# Run periodically to keep the system healthy

set -e

CONFIG_DIR=~/.config/scam_detector
DATA_DIR=~/Documents/scam-detector/data
BACKUP_DIR=~/Documents/scam-detector/backup_$(date +%Y%m%d_%H%M%S)

echo "=========================================="
echo "Job Scam Detector v3.1 Maintenance"
echo "Date: $(date)"
echo "=========================================="
echo ""

# --- [1/5] Check GeoIP Database ---
echo "[1/5] Checking GeoIP Database..."
if [ ! -f "$DATA_DIR/GeoLite2-Country.mmdb" ]; then
    echo "  WARNING: GeoLite2-Country.mmdb not found!"
    echo "  Email backtrace will be limited. Download from https://dev.maxmind.com/geoip/"
else
    DAYS_OLD=$(( ($(date +%s) - $(stat -c %Y "$DATA_DIR/GeoLite2-Country.mmdb")) / 86400 ))
    if [ $DAYS_OLD -gt 90 ]; then
        echo "  WARNING: GeoIP database is $DAYS_OLD days old."
        echo "  MaxMind recommends refreshing every 90 days."
    else
        echo "  OK - Database is ${DAYS_OLD} days old"
    fi
fi

# --- [2/5] Vacuum SQLite Database ---
echo "[2/5] Vacuuming SQLite Database..."
if [ -f "$CONFIG_DIR/scan_history.db" ]; then
    python3 -c "import sqlite3; sqlite3.connect('$CONFIG_DIR/scan_history.db').execute('VACUUM')"
    SIZE=$(du -h "$CONFIG_DIR/scan_history.db" | cut -f1)
    echo "  Done - Database size: $SIZE"
else
    echo "  No database found - skipping"
fi

# --- [3/5] Backup Configuration ---
echo "[3/5] Backing up configuration..."
mkdir -p "$BACKUP_DIR"
cp -r "$CONFIG_DIR"/* "$BACKUP_DIR/" 2>/dev/null || true
echo "  Backed up to: $BACKUP_DIR"
echo "  Tip: Delete old backups manually after confirming new one works"

# --- [4/5] Check Dependencies ---
echo "[4/5] Checking dependencies..."
cd ~/Documents/scam-detector
pip install -q --upgrade -r requirements.txt 2>/dev/null || echo "  Note: Some dependencies may need manual update"
pip list --outdated 2>/dev/null | grep -qE "(customtkinter|dnspython|whois|geoip2|sqlite3)" && echo "  WARNING: Updates available" || echo "  OK - All dependencies current"

# --- [5/5] Clean Temp Files ---
echo "[5/5] Cleaning temporary files..."
find "$CONFIG_DIR" -name "*.tmp" -delete 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
echo "  Done"

echo ""
echo "=========================================="
echo "Maintenance complete!"
echo "=========================================="
echo ""
echo "Next scheduled check: 30 days"
echo "Tip: Add to crontab for automatic weekly runs:"
echo "  0 3 * * 0 $HOME/Documents/scam-detector/maintenance.sh >> /var/log/scam-detector-maint.log 2>&1"
