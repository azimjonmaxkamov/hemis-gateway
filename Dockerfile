# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
FROM python:3.12-slim

LABEL org.opencontainers.image.title="HEMIS API Gateway" \
      org.opencontainers.image.description="Secure, filtered API gateway and control panel for the HEMIS university information system" \
      org.opencontainers.image.authors="Azimjon Makhkamov <raqamlivodiy@gmail.com>" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="1.1.1"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY data ./data

RUN useradd -r -u 10001 gateway && chown -R gateway /srv/data
USER gateway

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/healthz')" || exit 1

CMD ["sh", "-c", "python -m app.cli init && exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers ${WORKERS:-4} --proxy-headers --forwarded-allow-ips='*' --no-server-header"]
