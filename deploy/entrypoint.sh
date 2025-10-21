#!/usr/bin/env bash
set -e

echo "=== Starting Shift Scheduler Backend ==="

# Variables de entorno para Postgres (Railway usa DATABASE_URL)
if [ -n "$DATABASE_URL" ]; then
    echo "Using DATABASE_URL from Railway"
else
    echo "Waiting for Postgres at $POSTGRES_HOST:$POSTGRES_PORT ..."
    python - <<'PY'
import os, time, socket
host = os.environ.get("POSTGRES_HOST","db")
port = int(os.environ.get("POSTGRES_PORT","5432"))
for i in range(60):
    try:
        with socket.create_connection((host, port), timeout=2):
            print("DB is up.")
            break
    except OSError:
        print("DB not ready, sleeping 2s...")
        time.sleep(2)
else:
    raise SystemExit("Postgres did not become available in time.")
PY
fi

echo "Running migrations..."
python manage.py migrate --noinput

echo "Collecting static files..."
python manage.py collectstatic --noinput --clear || true

echo "Starting Gunicorn on port ${PORT:-8000}..."
exec gunicorn core.wsgi:application --bind 0.0.0.0:${PORT:-8000} --workers 3 --timeout 120