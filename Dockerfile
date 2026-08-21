FROM mcr.microsoft.com/playwright/python:v1.62.0-noble

WORKDIR /app
ENV SCANNER_BROWSER=1
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY --chown=pwuser:pwuser . .

# The official Playwright image already contains browser binaries. Run the
# scanner as the non-root Playwright user so Chromium can keep its sandbox.
USER pwuser

ENTRYPOINT ["python3", "main_v2.py"]
CMD ["--help"]
