FROM mcr.microsoft.com/playwright/python:v1.62.0-noble AS builder

WORKDIR /build

COPY pyproject.toml README.md ./
COPY main_v2.py ./
COPY config ./config
COPY core ./core
COPY layers ./layers
COPY plugins ./plugins
COPY policies ./policies
COPY workflows ./workflows

RUN python -m pip install --no-cache-dir 'build>=1.5,<2' \
    && python -m build --wheel --outdir /dist


FROM mcr.microsoft.com/playwright/python:v1.62.0-noble AS runtime

WORKDIR /app
ENV SCANNER_BROWSER=1
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r requirements.txt

COPY --from=builder /dist/*.whl /tmp/
RUN python -m pip install --no-cache-dir --no-deps /tmp/*.whl \
    && rm -f /tmp/*.whl \
    && mkdir -p /app/reports \
    && chown -R pwuser:pwuser /app

USER pwuser

ENTRYPOINT ["web-vuln-scanner"]
CMD ["--help"]
