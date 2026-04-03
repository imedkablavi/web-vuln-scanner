# Base Image with Python and Playwright dependencies
FROM mcr.microsoft.com/playwright/python:v1.40.0-jammy

WORKDIR /app
ENV SCANNER_BROWSER=1
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Install System Dependencies
RUN apt-get update && apt-get install -y \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Copy Requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Application Code
COPY . .

# Install Playwright Browsers (can be skipped at runtime if SCANNER_BROWSER=0)
RUN if [ "$SCANNER_BROWSER" != "0" ]; then playwright install chromium; fi

# Entry Point
ENTRYPOINT ["python3", "main_v2.py"]
CMD ["--help"]
