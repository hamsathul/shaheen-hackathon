FROM mcr.microsoft.com/playwright/python:v1.65.2-noble

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:$PATH

COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY shaheen ./shaheen
COPY data ./data
RUN uv sync --frozen --no-dev && playwright install chromium

RUN mkdir -p /app/evidence /app/var && chmod 1777 /app/evidence /app/var
ENV HOME=/tmp

ENTRYPOINT ["shaheen"]
CMD ["--help"]
