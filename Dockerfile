# ---------- Stage 1: Builder ----------
FROM python:3.11-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy dependency file and install into /install to optimize cache
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Copy application code
COPY . /build/app

# ---------- Stage 2: Runtime ----------
FROM python:3.11-slim

# Set timezone to UTC
ENV TZ=UTC
RUN ln -snf /usr/share/zoneinfo/UTC /etc/localtime && echo "UTC" > /etc/timezone

# Install minimal system deps including cron
RUN apt-get update && apt-get install -y --no-install-recommends \
    cron \
    procps \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Create directories for app, data and cron mountpoints
RUN mkdir -p /app /data /cron /var/log

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Ensure Python uses installed site-packages
ENV PATH=/usr/local/bin:$PATH
ENV PYTHONPATH=/usr/local/lib/python3.11/site-packages

# Copy application code into image
COPY --from=builder /build/app /app
WORKDIR /app

# Install cron file (the file will be copied into /etc/cron.d/ in the build)
COPY cron/2fa-cron /etc/cron.d/2fa-cron
COPY cron/refresh_seed.sh /app/cron/refresh_seed.sh
RUN chmod 0644 /etc/cron.d/2fa-cron && chmod +x /app/cron/refresh_seed.sh

# Copy entrypoint/start script
COPY start.sh /start.sh
RUN chmod +x /start.sh

# Create volume mount points for persistence
VOLUME ["/data", "/cron"]

# Expose port required by the assignment
EXPOSE 8080

# Use a simple unprivileged user if desired (optional)
# RUN useradd --create-home appuser && chown -R appuser:appuser /app /data
# USER appuser

# Final entrypoint: start cron (background) then uvicorn (foreground)
ENTRYPOINT ["/start.sh"]
