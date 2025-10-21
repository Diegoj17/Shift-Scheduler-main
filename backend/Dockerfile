FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Opción A: sin requirements.txt (instala paquetes base)
RUN pip install --no-cache-dir \
    django==5.2.7 \
    djangorestframework \
    djangorestframework-simplejwt \
    psycopg2-binary \
    python-dotenv \
    gunicorn \
    django-cors-headers

# Copia el proyecto Django
COPY ./backend /app

# Copia entrypoint con permisos de ejecución listos
COPY --chmod=0755 ./deploy/entrypoint.sh /entrypoint.sh

# Crea usuario no-root y úsalo
RUN useradd -m appuser
USER appuser

EXPOSE 8000
CMD ["/entrypoint.sh"]
