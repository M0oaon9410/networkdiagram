#!/bin/sh
# Daily copy of ./data (diagrams, accounts, sessions, mail settings, audit log) into ./backups,
# keeping the last KEEP_DAYS days. Run from cron; see README.
set -eu
cd "$(dirname "$0")/.."
KEEP_DAYS="${KEEP_DAYS:-30}"
mkdir -p backups
chmod 700 backups
out="backups/netplan-data-$(date +%Y%m%d-%H%M%S).tgz"
# the archive holds password hashes and the SMTP password, so only this user may read it
umask 077
tar -czf "$out.tmp" data
mv "$out.tmp" "$out"
find backups -name 'netplan-data-*.tgz' -mtime +"$KEEP_DAYS" -delete
echo "$(date '+%F %T') saved $out"
