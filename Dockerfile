# syntax=docker/dockerfile:1.7

FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /build

# Tạo virtualenv riêng
RUN python -m venv /opt/venv

# Copy requirements.txt từ thư mục gốc (nơi chứa Dockerfile)
COPY requirements.txt .

RUN /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt


FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/opt/venv/bin:$PATH"

# --- THÊM DÒNG NÀY ĐỂ CÀI CURL ---
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Biến môi trường mặc định (có thể override bằng .env hoặc compose)
ENV API_HOST=0.0.0.0
ENV API_PORT=8000
ENV LOG_LEVEL=INFO

WORKDIR /app

# Tạo user non‑root
RUN addgroup --system appgroup \
    && adduser --system --ingroup appgroup --home /app appuser

# Copy virtualenv từ builder
COPY --from=builder /opt/venv /opt/venv

# Copy toàn bộ mã nguồn (giữ nguyên cấu trúc thư mục)
COPY src/ ./src/
COPY uid_whitelist.csv ./

# Cấp quyền cho user
RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 8000

# Healthcheck dùng endpoint /health
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).read()" || exit 1

# Chạy main.py (đã bao gồm cả MQTT và FastAPI)
CMD ["python", "src/access_gate/main.py"]