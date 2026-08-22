# Lensint - Advanced Image Forensics, AI Detection & Threat Intelligence
FROM python:3.11-slim

LABEL maintainer="Lensint Forensics Team"
LABEL description="Headless automated image forensics, AI detection, and threat intelligence service"

WORKDIR /app

# Install system dependencies for OpenCV and image operations
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 \
    libglib2.0-0 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt pyproject.toml setup.py README.md ./
COPY lensint/ ./lensint/

RUN pip install --no-cache-dir -e .

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["lensint"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
