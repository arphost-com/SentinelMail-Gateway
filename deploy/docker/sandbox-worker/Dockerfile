# syntax=docker/dockerfile:1.7
# Playwright + Chromium pre-installed in this image — saves us from a 5-min
# `playwright install chromium` step on every build and avoids most font /
# system-lib gotchas. Image is ~1.2 GB; isolated to this service so the
# light worker stays small.
FROM mcr.microsoft.com/playwright/python:v1.49.0-noble

# Non-root user. The base image has a `pwuser` already created.
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && python -m venv /opt/venv \
    && install -d -o pwuser -g pwuser /app
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/opt/venv/bin:${PATH}"

COPY --chown=pwuser:pwuser workers/sandbox-worker/requirements.txt /app/
RUN pip install -r requirements.txt

COPY --chown=pwuser:pwuser workers/sandbox-worker /app

USER pwuser
HEALTHCHECK --interval=60s --timeout=10s --start-period=20s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"
CMD ["python", "-u", "worker.py"]
