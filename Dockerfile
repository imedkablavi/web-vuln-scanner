FROM mcr.microsoft.com/playwright/python:v1.62.0-noble

WORKDIR /app
ENV SCANNER_BROWSER=1
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r requirements.txt

COPY --chown=pwuser:pwuser . .

# Install the same packaged entry point that wheel users receive. Runtime
# dependencies are already pinned above, so avoid resolving them a second time.
RUN python -m pip install --no-cache-dir --no-deps . \
    && mkdir -p /app/reports \
    && chown -R pwuser:pwuser /app

USER pwuser

ENTRYPOINT ["web-vuln-scanner"]
CMD ["--help"]
