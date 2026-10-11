# Multi-stage image for Sandbox Gateway API & Egress Filtering Proxy
FROM python:3.11-slim

WORKDIR /app

# Install security tools & dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY runtime/ /app/runtime/
COPY api/ /app/api/

ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1

EXPOSE 8000 8080

CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
