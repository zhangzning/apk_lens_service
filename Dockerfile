# syntax=docker/dockerfile:1
FROM ghcr.io/astral-sh/uv:0.11.8 AS uv

FROM python:3.12-slim-trixie AS dependencies
COPY --from=uv /uv /usr/local/bin/uv
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project

FROM python:3.12-slim-trixie AS jadx
ADD --checksum=sha256:545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974 \
    https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip /tmp/jadx.zip
RUN python -m zipfile -e /tmp/jadx.zip /opt/jadx && chmod 0755 /opt/jadx/bin/jadx

FROM python:3.12-slim-trixie AS runtime
RUN groupadd --gid 10001 apk-lens \
    && useradd --uid 10001 --gid 10001 --home-dir /work --no-create-home apk-lens
WORKDIR /app
COPY --from=dependencies /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:${PATH}" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-m", "apk_lens_service"]

FROM runtime AS api
RUN install -d -m 0700 -o 10001 -g 10001 /var/lib/apk-lens/jobs
COPY apk_lens_service/ /app/apk_lens_service/
USER 10001:10001

FROM runtime AS worker
RUN apt-get update \
    && apt-get install -y --no-install-recommends aapt binutils default-jre-headless \
    && rm -rf /var/lib/apt/lists/*
COPY --from=jadx /opt/jadx /opt/jadx
COPY apk_lens_service/ /app/apk_lens_service/
ENV HOME=/work TMPDIR=/work APK_LENS_SERVICE_JADX_BIN=/opt/jadx/bin/jadx
USER 10001:10001
