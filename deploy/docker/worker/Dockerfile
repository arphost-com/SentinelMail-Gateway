# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS build
WORKDIR /src
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
COPY workers/sandbox/requirements.txt ./
RUN pip install --prefix=/install -r requirements.txt

FROM python:3.12-slim
# libzbar0 is the runtime that pyzbar wraps for QR/barcode decode.
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
      libzbar0 \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd -g 10003 sentinelw && \
    useradd -u 10003 -g sentinelw -m -s /sbin/nologin sentinelw && \
    mkdir -p /app && chown -R sentinelw:sentinelw /app
WORKDIR /app
COPY --from=build /install /usr/local
COPY --chown=sentinelw:sentinelw workers/sandbox /app
USER sentinelw
ENV PYTHONUNBUFFERED=1
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"
CMD ["python", "-u", "worker.py"]
