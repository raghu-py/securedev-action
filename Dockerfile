FROM python:3.12-slim

LABEL org.opencontainers.image.title="SecureDev Action"
LABEL org.opencontainers.image.description="Self-contained security scanner for GitHub Actions"
LABEL org.opencontainers.image.authors="Raghu Soni"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV SECUREDEV_RUNNING_IN_ACTION=1

WORKDIR /app
COPY securedev_action /app/securedev_action
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh \
    && useradd --create-home --shell /bin/sh securedev \
    && chown -R securedev:securedev /app

USER securedev
ENTRYPOINT ["/entrypoint.sh"]
