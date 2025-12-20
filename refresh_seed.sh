#!/usr/bin/env bash
set -e
# Example cron helper - make sure encrypted_seed.txt exists and call decrypt script.
ENCRYPTED_FILE="/app/encrypted_seed.txt"
if [ -f "$ENCRYPTED_FILE" ]; then
  echo "$(date -u +'%Y-%m-%dT%H:%M:%SZ') running decrypt"
  # run decrypt script with system python
  python /app/decrypt_seed.py || echo "decrypt failed" >&2
fi
