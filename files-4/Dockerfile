FROM python:3.11-slim

LABEL maintainer="Rajnish Singh"
LABEL description="HyPQ-Mess: Hybrid Post-Quantum Secure Messaging System"

WORKDIR /app

# Install system dependencies for liboqs
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt || \
    pip install --no-cache-dir cryptography cbor2 rich prompt_toolkit numpy matplotlib

# Try to install pyoqs (may fail in some environments — fallback is included)
RUN pip install pyoqs || echo "pyoqs unavailable; using Kyber simulation fallback"

COPY . .
RUN pip install -e . --no-deps

EXPOSE 8080

# Default: run server on port 8080
CMD ["python", "-m", "hy_pq_mess", "server", "8080"]
