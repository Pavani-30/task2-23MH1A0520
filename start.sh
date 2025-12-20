#!/usr/bin/env bash
set -e

# Ensure log dir exists
mkdir -p /var/log

# Make cron file effective (if present)
if [ -f /etc/cron.d/2fa-cron ]; then
  chmod 0644 /etc/cron.d/2fa-cron
  # install the cron file
  crontab /etc/cron.d/2fa-cron || true
fi

# Start cron in background
echo "Starting cron..."
cron

# Start the API server (uvicorn) in foreground so container keeps running
echo "Starting uvicorn..."
exec uvicorn app:app --host 0.0.0.0 --port 8080
