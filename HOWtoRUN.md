# Hướng dẫn chạy Access Gate Service

## Yêu cầu hệ thống

- Python 3.11 hoặc cao hơn 
- Docker và Docker Compose
- Kết nối Internet để truy cập HiveMQ broker
- Kết nối vào iPhone hotspot của Product để tích hợp với các nhóm khác

## 1. Cấu hình biến môi trường

Tạo file `.env` trong thư mục gốc với nội dung sau:

```ini
# MQTT Broker (HiveMQ)
MQTT_HOST=...
MQTT_PORT=...
MQTT_USERNAME=...
MQTT_PASSWORD=...

# Topics
INPUT_TOPIC=smart-campus/raw/access/rfid-uid
OUTPUT_TOPIC=smart-campus/events/access

# File whitelist
WHITELIST_CSV=uid_whitelist.csv

# REST API
API_HOST=0.0.0.0
API_PORT=8000

# Core Business integration (thay IP khi demo)
CORE_SERVICE_URL=http://localhost:8000 #(ví dụ http://172.20.10.5:8000)
CORE_REQUEST_TIMEOUT=3.0

# Logging
LOG_LEVEL=INFO
```

## 2. Chạy service bằng Python thuần (phát triển)

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

```bash
# Bước 1: Tạo và kích hoạt virtual environment (khuyến nghị)
python -m venv venv
source venv/bin/activate      # Linux/Mac
venv\Scripts\activate         # Windows

# Bước 2: Cài đặt dependencies
pip install -r requirements.txt

# Bước 3: Chạy service
python src/access_gate/main.py
```
Service sẽ khởi động và hiển thị log:
 - Kết nối MQTT thành công
 - FastAPI chạy tại http://0.0.0.0:8000
 
## 3. Chạy service bằng Docker Compose

```bash
# Bước 1: Đứng ở thư mục gốc (chứa docker-compose.yml)
cd access-gate-service

# Bước 2: Build và chạy container
docker compose up -d --build

# Bước 3: Kiểm tra trạng thái
docker compose ps

# Bước 4: Xem log (nếu cần)
docker compose logs -f
```

Container sẽ có tên access-gate-service và expose port 8000.

## 4. Kiểm tra service đã chạy

Mở terminal khác (hoặc dùng curl/PowerShell) và gọi:

```bash
# Health check
curl http://localhost:8000/health #curl http://26.51.14.74:8000/health

# Lấy 5 log gần nhất
curl http://localhost:8000/access/logs/recent?limit=5 -o logs.json

# Kiểm tra trạng thái cổng
curl http://localhost:8000/gates/GATE-01/status

# Lấy thông tin thẻ (thay CARD-SV001 bằng mã có trong whitelist)
curl http://localhost:8000/cards/CARD-SV001
```

Tất cả các endpoint đều trả về JSON và HTTP status 200 nếu thành công.

## 5. Tích hợp với Core Business

- Khi có thẻ quẹt (MQTT message), service sẽ tự động gọi POST /access/check đến Core Business.
- Nếu Core Business trả về allow: true → publish granted.
- Nếu Core Business trả về allow: false hoặc không phản hồi (timeout, lỗi) → publish denied (fallback an toàn).
- Để kiểm tra tích hợp, bạn có thể chạy Core Business service trước, sau đó cập nhật CORE_SERVICE_URL trong .env và khởi động lại Access Gate.

## 6. Dừng service

Chạy bằng Python nhấn `Ctrl + C` trong terminal

Chạy bằng Docker:

```bash
# Dừng container và xóa chúng(Không xóa image đã build)
docker compose down
# Chỉ dừng container, không xóa
docker compose stop
```

## 7. Database 

```bash

# Kiểm tra danh sách bảng
docker exec -it access-db psql -U access_user -d access_db -c "\dt"

# Kiểm tra cấu trúc bảng
docker exec -it access-db psql -U access_user -d access_db -c "\d access_logs"

# Truy vấn dữ liệu từ psql tương tác
docker exec -it access-db psql -U access_user -d access_db
SELECT "logId", "cardId", status, timestamp FROM access_logs ORDER BY timestamp DESC LIMIT 5;
```