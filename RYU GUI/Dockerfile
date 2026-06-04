# ============================================================
# Ryu SDN Dashboard — Django + Channels container
# ============================================================
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=ryu_dashboard.settings

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
# torch/PyG are large — install them after the rest for better cache hits
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

RUN python manage.py collectstatic --noinput || true

EXPOSE 8000
CMD ["daphne", "-b", "0.0.0.0", "-p", "8000", "ryu_dashboard.asgi:application"]
