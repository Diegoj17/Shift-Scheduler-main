#!/usr/bin/env bash
set -e
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
echo "Running migrations..."
python manage.py migrate --noinput
echo "Collecting static files..."
python manage.py collectstatic --noinput || true
echo "Starting Gunicorn..."
exec gunicorn core.wsgi:application --bind 0.0.0.0:8000 --workers 3
