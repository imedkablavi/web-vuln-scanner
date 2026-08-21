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

# Reports, traces, screenshots and the default scanner log are runtime data.
# Keep the official Playwright non-root user while making /app writable.
RUN mkdir -p /app/reports \
    && chown -R pwuser:pwuser /app

USER pwuser

ENTRYPOINT ["python3", "main_v2.py"]
CMD ["--help"]
