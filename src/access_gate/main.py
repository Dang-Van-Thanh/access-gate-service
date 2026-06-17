#!/usr/bin/env python3
"""
AccessGate Service – Nhận UID RFID từ HiveMQ, gọi Core Business để thẩm định quyền,
lưu log vào PostgreSQL, expose REST API cho Core Business,
và publish sự kiện qua MQTT để Analytics có thể consume (queue async).
"""

import csv
import json
import logging
import os
import ssl
import threading
import uuid
import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional
from contextlib import asynccontextmanager

import paho.mqtt.client as mqtt
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
import uvicorn
import httpx
from databases import Database
import sqlalchemy

# ==================== DETERMINE PROJECT ROOT ====================
_current_dir = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(_current_dir))

# Load .env from project root
dotenv_path = os.path.join(PROJECT_ROOT, ".env")
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)
else:
    load_dotenv()

# ==================== LOAD ENV ====================
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("access-gate")

# MQTT
MQTT_HOST = os.getenv("MQTT_HOST")
MQTT_PORT = int(os.getenv("MQTT_PORT", "8883"))
MQTT_USERNAME = os.getenv("MQTT_USERNAME")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD")
INPUT_TOPIC = os.getenv("INPUT_TOPIC", "smart-campus/raw/access/rfid-uid")
OUTPUT_TOPIC = os.getenv("OUTPUT_TOPIC", "smart-campus/events/access")
PUBLISH_ENABLED = os.getenv("PUBLISH_ENABLED", "true").lower() == "true"  # bật mặc định

# Whitelist CSV
WHITELIST_CSV_ENV = os.getenv("WHITELIST_CSV", "uid_whitelist.csv")
if not os.path.isabs(WHITELIST_CSV_ENV):
    WHITELIST_CSV = os.path.join(PROJECT_ROOT, WHITELIST_CSV_ENV)
else:
    WHITELIST_CSV = WHITELIST_CSV_ENV

# REST API
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))

# Core Business integration
CORE_SERVICE_URL = os.getenv("CORE_SERVICE_URL", "http://localhost:8000")
CORE_REQUEST_TIMEOUT = float(os.getenv("CORE_REQUEST_TIMEOUT", "3.0"))
AUTH_TOKEN = os.getenv("AUTH_TOKEN", "")
if not AUTH_TOKEN:
    logger.warning("AUTH_TOKEN chưa được cấu hình, gọi Core sẽ bị lỗi 401")

# Database
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./access_logs.db")
database = Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

# Define table
access_log_table = sqlalchemy.Table(
    "access_logs",
    metadata,
    sqlalchemy.Column("logId", sqlalchemy.String(36), primary_key=True),
    sqlalchemy.Column("cardId", sqlalchemy.String(50), index=True),
    sqlalchemy.Column("gateId", sqlalchemy.String(20), index=True),
    sqlalchemy.Column("direction", sqlalchemy.String(10)),
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime(timezone=True), index=True),
    sqlalchemy.Column("status", sqlalchemy.String(20), index=True),
    sqlalchemy.Column("note", sqlalchemy.String(300), nullable=True),
    sqlalchemy.Column("holderName", sqlalchemy.String(100)),
    sqlalchemy.Column("holderRole", sqlalchemy.String(30)),
    sqlalchemy.Column("readerModel", sqlalchemy.String(80)),
    sqlalchemy.Column("reason", sqlalchemy.String(100), nullable=True),
)

# Create tables
engine = sqlalchemy.create_engine(DATABASE_URL)
metadata.create_all(engine)

# ==================== GLOBAL DATA STORES ====================
access_logs = []  # RAM cache, tối đa 200
MAX_LOG_SIZE = 200
whitelist: Dict[str, dict] = {}

# Queue for async DB insert
log_queue = asyncio.Queue()

# ==================== HELPER FUNCTIONS ====================
def load_whitelist(csv_path: str) -> Dict[str, dict]:
    data = {}
    if not os.path.exists(csv_path):
        logger.error(f"Không tìm thấy file whitelist: {csv_path}")
        return data
    try:
        with open(csv_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row.get("uid", "").strip()
                if uid:
                    data[uid] = {
                        "student_id": row.get("student_id", "").strip(),
                        "full_name": row.get("full_name", "").strip(),
                        "class_name": row.get("class_name", "").strip(),
                    }
        logger.info(f"Đã tải {len(data)} UID từ {csv_path}")
    except Exception as e:
        logger.exception(f"Lỗi đọc file CSV: {e}")
    return data

def generate_event_id() -> str:
    return f"access-event-{uuid.uuid4().hex[:12]}"

def build_log_entry(processed: dict) -> dict:
    card_id = processed.get("cardId")
    if not card_id:
        student_id = processed.get('student_id')
        if student_id and isinstance(student_id, str):
            card_id = f"CARD-{student_id[-6:]}"
        else:
            card_id = "CARD-UNKNOWN"

    holder_name = processed.get("full_name") or "Unknown"
    holder_role = "STUDENT" if processed.get("student_id") else "GUEST"
    reader_model = "RFID-RDR-V3.2"

    return {
        "logId": str(uuid.uuid4()),
        "cardId": card_id,
        "gateId": processed.get("door_id", "GATE-01"),
        "direction": processed.get("direction", "IN"),
        "timestamp": datetime.fromisoformat(processed.get("timestamp", datetime.now(timezone.utc).isoformat())),
        "status": "ALLOWED" if processed.get("access_result") == "granted" else "DENIED",
        "note": processed.get("reason", ""),
        "holderName": holder_name,
        "holderRole": holder_role,
        "readerModel": reader_model,
        "reason": processed.get("reason"),
    }

def call_core_policy(card_id: str, gate_id: str, direction: str, timestamp: str) -> Optional[dict]:
    request_id = str(uuid.uuid4())
    payload = {
        "requestId": request_id,
        "cardId": card_id,
        "gateId": gate_id,
        "direction": direction,
        "timestamp": timestamp
    }
    headers = {"Authorization": f"Bearer {AUTH_TOKEN}"} if AUTH_TOKEN else {}
    try:
        with httpx.Client(timeout=CORE_REQUEST_TIMEOUT) as client:
            resp = client.post(
                f"{CORE_SERVICE_URL}/access/check",
                json=payload,
                headers=headers
            )
            if resp.status_code == 200:
                data = resp.json()
                logger.debug(f"Core response: {data}")
                return data
            else:
                logger.error(f"Core trả về lỗi {resp.status_code}: {resp.text}")
                return None
    except httpx.TimeoutException:
        logger.error("Core service timeout (%.1fs)", CORE_REQUEST_TIMEOUT)
        return None
    except Exception as e:
        logger.exception(f"Lỗi khi gọi Core: {e}")
        return None

def enrich_output(raw_payload: dict) -> dict:
    raw_event_id = raw_payload.get("event_id")
    uid = raw_payload.get("uid", "").strip()
    door_id = raw_payload.get("door_id", "unknown")
    location = raw_payload.get("location", "unknown")
    direction = raw_payload.get("direction", "unknown")
    timestamp = raw_payload.get("timestamp", datetime.now(timezone.utc).isoformat())

    student_id = None
    full_name = None
    class_name = None
    card_id = "CARD-UNKNOWN"
    if uid in whitelist:
        info = whitelist[uid]
        student_id = info["student_id"]
        full_name = info["full_name"]
        class_name = info["class_name"]
        card_id = f"CARD-{student_id[-6:]}"

    core_decision = call_core_policy(card_id, door_id, direction, timestamp)

    if core_decision is not None:
        if core_decision.get("allow") is True:
            access_result = "granted"
            reason = f"policy_{core_decision.get('reasonCode', 'ALLOWED')}"
        else:
            access_result = "denied"
            reason = f"policy_{core_decision.get('reasonCode', 'DENIED')}"
    else:
        logger.warning(f"Core không phản hồi, từ chối UID {uid} (card {card_id})")
        access_result = "denied"
        reason = "core_unavailable"

    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    output = {
        "event_id": generate_event_id(),
        "event_type": "access.swipe.processed",
        "source_service": "team-gate",
        "timestamp": now_iso,
        "raw_event_id": raw_event_id,
        "uid": uid,
        "student_id": student_id,
        "full_name": full_name,
        "class_name": class_name,
        "door_id": door_id,
        "location": location,
        "direction": direction,
        "access_result": access_result,
        "reason": reason,
        "cardId": card_id
    }
    return output

# ==================== DB BACKGROUND WORKER ====================
async def log_worker():
    """Liên tục lấy log từ queue và insert vào DB."""
    while True:
        log_entry = await log_queue.get()
        try:
            query = access_log_table.insert().values(**log_entry)
            await database.execute(query)
        except Exception as e:
            logger.exception(f"Lỗi insert log vào DB: {e}")
        finally:
            log_queue.task_done()

# ==================== MQTT CALLBACKS ====================
mqtt_client = None
loop = None  # sẽ được set trong lifespan

def on_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
        logger.info("Kết nối MQTT thành công")
        client.subscribe(INPUT_TOPIC, qos=1)
        logger.info(f"Đã subscribe topic: {INPUT_TOPIC}")
    else:
        logger.error(f"Kết nối MQTT thất bại, reason_code: {reason_code}")

def on_message(client, userdata, msg):
    logger.info(f"Nhận message từ {msg.topic}")
    try:
        raw_payload = json.loads(msg.payload.decode("utf-8"))
    except json.JSONDecodeError as e:
        logger.error(f"JSON không hợp lệ: {e}")
        return

    required_fields = ["event_id", "event_type", "timestamp", "uid", "door_id", "direction"]
    missing = [f for f in required_fields if f not in raw_payload]
    if missing:
        logger.warning(f"Thiếu field bắt buộc: {missing} - payload: {raw_payload}")
        return

    # Xử lý nghiệp vụ
    output = enrich_output(raw_payload)

    # Lưu vào RAM cache (sync)
    log_entry = build_log_entry(output)
    access_logs.insert(0, log_entry)
    if len(access_logs) > MAX_LOG_SIZE:
        access_logs.pop()

    # Gửi vào queue để insert DB (nếu DB đã kết nối)
    if loop and database.is_connected:
        asyncio.run_coroutine_threadsafe(log_queue.put(log_entry), loop)
    else:
        logger.warning("Database chưa sẵn sàng, log chỉ lưu RAM")

    # Publish sự kiện để Analytics consume (queue async qua MQTT)
    if PUBLISH_ENABLED:
        result = mqtt_client.publish(OUTPUT_TOPIC, payload=json.dumps(output, ensure_ascii=False), qos=1)
        if result.rc == mqtt.MQTT_ERR_SUCCESS:
            logger.info(f"Đã publish tới {OUTPUT_TOPIC}: {output['access_result']} - UID {output['uid']}")
        else:
            logger.error(f"Publish thất bại, mã lỗi: {result.rc}")

    logger.debug(f"Output: {json.dumps(output, indent=2, ensure_ascii=False)}")

def run_mqtt():
    global mqtt_client
    mqtt_client = mqtt.Client(protocol=mqtt.MQTTv5)
    mqtt_client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
    mqtt_client.tls_set(tls_version=ssl.PROTOCOL_TLS_CLIENT)
    mqtt_client.on_connect = on_connect
    mqtt_client.on_message = on_message

    try:
        mqtt_client.connect(MQTT_HOST, MQTT_PORT)
        mqtt_client.loop_forever()
    except Exception as e:
        logger.exception(f"MQTT loop failed: {e}")

# ==================== FASTAPI MODELS ====================
class AccessLog(BaseModel):
    logId: str
    cardId: str
    gateId: str
    direction: str
    timestamp: str
    status: str
    note: Optional[str] = None

class AccessLogPage(BaseModel):
    items: List[AccessLog]
    nextCursor: Optional[str]
    hasMore: bool

class AccessLogDetail(AccessLog):
    holderName: str
    holderRole: str
    readerModel: str

class GateStatus(BaseModel):
    gateId: str
    status: str
    lastActivityAt: str
    firmwareVersion: str

class CardDetail(BaseModel):
    cardId: str
    holderName: str
    holderRole: str
    status: str
    issuedAt: str
    expiresAt: str

# ==================== FASTAPI APP ====================
@asynccontextmanager
async def lifespan(app: FastAPI):
    global loop
    loop = asyncio.get_running_loop()

    # Kết nối DB
    await database.connect()
    logger.info("Đã kết nối database")

    # Khởi tạo worker xử lý log queue
    worker_task = asyncio.create_task(log_worker())

    # Start MQTT thread
    mqtt_thread = threading.Thread(target=run_mqtt, daemon=True)
    mqtt_thread.start()

    yield

    # Shutdown
    worker_task.cancel()
    await database.disconnect()
    if mqtt_client:
        mqtt_client.disconnect()
        mqtt_client.loop_stop()

app = FastAPI(
    title="Access Gate Service",
    version="1.0.0",
    description="Smart Campus Access Gate - MQTT + REST API + PostgreSQL",
    lifespan=lifespan
)

@app.get("/health", tags=["system"])
async def health():
    return {"status": "ok", "service": "access-gate-service", "time": datetime.now(timezone.utc).isoformat()}

@app.get("/access/logs/recent", response_model=AccessLogPage, tags=["access-logs"])
async def get_access_logs_recent(
    cursor: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100)
):
    items = access_logs[:limit]
    has_more = len(access_logs) > limit
    next_cursor = "dummy_cursor" if has_more else None
    return AccessLogPage(items=items, nextCursor=next_cursor, hasMore=has_more)

@app.get("/access/logs/{logId}", response_model=AccessLogDetail, tags=["access-logs"])
async def get_access_log_by_id(logId: str):
    for log in access_logs:
        if log["logId"] == logId:
            return AccessLogDetail(**log)
    raise HTTPException(status_code=404, detail="Log not found")

@app.get("/gates/{gateId}/status", response_model=GateStatus, tags=["device-monitoring"])
async def get_gate_status(gateId: str):
    if not gateId.startswith("GATE-"):
        raise HTTPException(status_code=400, detail="Invalid gateId format")
    return GateStatus(
        gateId=gateId,
        status="CLOSED",
        lastActivityAt=datetime.now(timezone.utc).isoformat(),
        firmwareVersion="gate-fw-v1.4.2"
    )

@app.get("/cards/{cardId}", response_model=CardDetail, tags=["device-monitoring"])
async def get_card_detail(cardId: str):
    if not cardId.startswith("CARD-"):
        raise HTTPException(status_code=400, detail="Invalid cardId format")
    suffix = cardId[5:]
    for uid, info in whitelist.items():
        if info["student_id"].endswith(suffix):
            return CardDetail(
                cardId=cardId,
                holderName=info["full_name"],
                holderRole="STUDENT",
                status="ACTIVE",
                issuedAt="2025-09-01T08:00:00Z",
                expiresAt="2029-09-01T17:00:00Z"
            )
    raise HTTPException(status_code=404, detail="Card not found")

def run_api():
    uvicorn.run(app, host=API_HOST, port=API_PORT)

# ==================== MAIN ====================
def main():
    global whitelist
    whitelist = load_whitelist(WHITELIST_CSV)
    if not whitelist:
        logger.warning("Whitelist rỗng, mọi UID sẽ bị từ chối!")

    run_api()

if __name__ == "__main__":
    main()