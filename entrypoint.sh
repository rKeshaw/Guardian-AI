#!/bin/sh
# guardian/entrypoint.sh
#
# Runs as root briefly to ensure bind-mounted directories are writable by the
# guardian user (uid 1000), then drops privileges and starts the application.
#
# Why this is necessary:
#   Docker bind mounts (./data:/app/data, ./logs:/app/logs) are owned by the
#   host user that created them — usually root. The guardian user inside the
#   container cannot write to root-owned directories. Rather than running the
#   whole application as root, we fix ownership here once at startup.

set -e

echo "[entrypoint] Fixing permissions on /app/data and /app/logs ..."
chown -R guardian:guardian /app/data /app/logs 2>/dev/null || true
chmod 755 /app/data /app/logs 2>/dev/null || true

echo "[entrypoint] Starting Guardian AI as guardian user ..."
exec gosu guardian "$@"