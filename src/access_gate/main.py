#!/usr/bin/env python3
"""
AccessGate Service – Nhận UID RFID từ HiveMQ, kiểm tra whitelist,
gọi Core Business kiểm tra policy, lưu log vào PostgreSQL,
expose REST API, và publish sự kiện qua MQTT.
"""

import csv
import json
import logging
import os
import re
import ssl
import threading
import uuid
import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional
from contextlib import asynccontextmanager

import paho.mqtt.client as mqtt
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Depends
from pydantic import BaseModel
import uvicorn
import httpx
from databases import Database
import sqlalchemy

# ==================== DETERMINE PROJECT ROOT ====================
_current_dir = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(_current_dir))

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

MQTT_HOST = os.getenv("MQTT_HOST")
MQTT_PORT = int(os.getenv("MQTT_PORT", "8883"))
MQTT_USERNAME = os.getenv("MQTT_USERNAME")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD")
INPUT_TOPIC = os.getenv("INPUT_TOPIC", "smart-campus/raw/access/rfid-uid")
OUTPUT_TOPIC = os.getenv("OUTPUT_TOPIC", "smart-campus/events/access")
PUBLISH_ENABLED = os.getenv("PUBLISH_ENABLED", "true").lower() == "true"

WHITELIST_CSV_ENV = os.getenv("WHITELIST_CSV", "uid_whitelist.csv")
if not os.path.isabs(WHITELIST_CSV_ENV):
    WHITELIST_CSV = os.path.join(PROJECT_ROOT, WHITELIST_CSV_ENV)
else:
    WHITELIST_CSV = WHITELIST_CSV_ENV

API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))

CORE_SERVICE_URL = os.getenv("CORE_SERVICE_URL", "http://localhost:8000")
CORE_REQUEST_TIMEOUT = float(os.getenv("CORE_REQUEST_TIMEOUT", "3.0"))
AUTH_TOKEN = os.getenv("AUTH_TOKEN", "")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./access_logs.db")
database = Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

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

engine = sqlalchemy.create_engine(DATABASE_URL)
metadata.create_all(engine)

# ==================== GLOBAL DATA STORES ====================
access_logs = []          # RAM cache
MAX_LOG_SIZE = 200
whitelist: Dict[str, dict] = {}   # uid -> info
card_to_uid: Dict[str, str] = {}  # cardId -> uid
log_queue = asyncio.Queue()

# ==================== HELPER FUNCTIONS ====================
def _make_card_id(value: str) -> str:
    """
    Tạo cardId theo định dạng CARD-0000XX
    với XX là 2 chữ số cuối cùng của chuỗi value (student_id hoặc uid).
    Nếu không có đủ 2 chữ số, bổ sung số 0.
    """
    digits = re.sub(r'\D', '', value)
    if len(digits) >= 2:
        suffix = digits[-2:]  # lấy 2 chữ số cuối
    else:
        # Nếu không có đủ 2 chữ số, thêm số 0 vào trước
        suffix = digits.zfill(2)
    # Tạo cardId với 4 số 0 + suffix (tổng 6 chữ số)
    return f"CARD-0000{suffix}"

def load_whitelist(csv_path: str):
    global whitelist, card_to_uid
    data = {}
    card_map = {}
    if not os.path.exists(csv_path):
        logger.error(f"Không tìm thấy file whitelist: {csv_path}")
        whitelist = data
        card_to_uid = card_map
        return
    try:
        with open(csv_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row.get("uid", "").strip()
                if uid:
                    student_id = row.get("student_id", "").strip()
                    full_name = row.get("full_name", "").strip()
                    class_name = row.get("class_name", "").strip()
                    data[uid] = {
                        "student_id": student_id,
                        "full_name": full_name,
                        "class_name": class_name,
                    }
                    card_id = _make_card_id(student_id) if student_id else _make_card_id(uid)
                    card_map[card_id] = uid
        whitelist = data
        card_to_uid = card_map
        logger.info(f"Đã tải {len(data)} UID, {len(card_map)} thẻ")
    except Exception as e:
        logger.exception(f"Lỗi đọc CSV: {e}")
        whitelist = {}
        card_to_uid = {}

def generate_event_id() -> str:
    return f"access-event-{uuid.uuid4().hex[:12]}"

def normalize_direction(direction: str) -> str:
    """Chuẩn hóa direction thành IN hoặc OUT (viết hoa)."""
    d = direction.strip().upper()
    if d == "IN":
        return "IN"
    return "OUT"

def normalize_timestamp(ts: str) -> str:
    """Chuẩn hóa timestamp về ISO 8601 với timezone UTC (dạng Z)."""
    try:
        if ts.endswith('Z'):
            dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        else:
            dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.isoformat(timespec="seconds").replace("+00:00", "Z")
    except Exception:
        return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

# ==================== GỌI CORE BUSINESS ====================
async def call_core_policy(card_id: str, gate_id: str, direction: str, timestamp: str) -> dict:
    """
    Gọi Core Business để kiểm tra policy thực tế.
    Trả về: {"allow": bool, "reason": str, "policyId": str|None}
    """
    norm_direction = normalize_direction(direction)
    norm_timestamp = normalize_timestamp(timestamp)

    payload = {
        "requestId": str(uuid.uuid4()),
        "cardId": card_id,
        "gateId": gate_id,
        "direction": norm_direction,
        "timestamp": norm_timestamp
    }
    headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}
    logger.debug(f"Gọi Core với payload: {payload}")

    async with httpx.AsyncClient(timeout=CORE_REQUEST_TIMEOUT) as client:
        try:
            resp = await client.post(
                f"{CORE_SERVICE_URL}/access/check",
                json=payload,
                headers=headers
            )
            resp.raise_for_status()
            data = resp.json()
            logger.info(f"Core phản hồi: {data}")
            return {
                "allow": data.get("allow", False),
                "reason": data.get("reasonCode", "unknown"),
                "policyId": data.get("policyId")
            }
        except httpx.HTTPStatusError as e:
            logger.error(f"Core trả về lỗi {e.response.status_code}: {e.response.text}")
            return {"allow": False, "reason": "core_error", "policyId": None}
        except Exception as e:
            logger.error(f"Gọi Core thất bại: {e}, fallback DENY")
            return {"allow": False, "reason": "core_unreachable", "policyId": None}

# ==================== XỬ LÝ LUỒNG MQTT ====================
async def process_swipe(raw_payload: dict):
    """Xử lý một lượt quẹt thẻ: kiểm tra whitelist, gọi Core, quyết định, log, publish."""
    # 1. VALIDATE
    required = ["event_id", "event_type", "timestamp", "uid", "door_id", "direction"]
    missing = [f for f in required if f not in raw_payload]
    if missing:
        logger.warning(f"Thiếu field: {missing} - {raw_payload}")
        return

    raw_event_id = raw_payload.get("event_id")
    uid = raw_payload.get("uid", "").strip()
    door_id = raw_payload.get("door_id", "unknown")
    location = raw_payload.get("location", "unknown")
    direction = raw_payload.get("direction", "unknown")
    timestamp = raw_payload.get("timestamp", datetime.now(timezone.utc).isoformat())

    # 2. Tạo cardId từ UID
    card_id = _make_card_id(uid)

    # 3. Kiểm tra whitelist trước
    info = whitelist.get(uid)
    if info:
        student_id = info.get("student_id")
        full_name = info.get("full_name")
        class_name = info.get("class_name")
        # UID hợp lệ → gọi Core để kiểm tra policy
        core_decision = await call_core_policy(card_id, door_id, direction, timestamp)
        allow = core_decision["allow"]
        core_reason = core_decision["reason"]

        if allow:
            access_result = "granted"
            reason = core_reason
        else:
            access_result = "denied"
            reason = core_reason
    else:
        # UID không có trong whitelist → từ chối ngay, không gọi Core
        student_id = full_name = class_name = None
        access_result = "denied"
        reason = "uid_not_in_whitelist"
        logger.warning(f"UID {uid} không có trong whitelist, từ chối")

    # 4. Tạo output event
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        output_ts = dt.isoformat(timespec="seconds").replace("+00:00", "Z")
    except Exception:
        dt = datetime.now(timezone.utc)
        output_ts = dt.isoformat(timespec="seconds").replace("+00:00", "Z")

    output = {
        "event_id": generate_event_id(),
        "event_type": "access.swipe.processed",
        "source_service": "team-gate",
        "timestamp": output_ts,
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

    # 5. Build log entry
    log_entry = {
        "logId": str(uuid.uuid4()),
        "cardId": card_id,
        "gateId": door_id,
        "direction": direction,
        "timestamp": dt,
        "status": "ALLOWED" if access_result == "granted" else "DENIED",
        "note": reason,
        "holderName": full_name or "Unknown",
        "holderRole": "STUDENT" if student_id else "GUEST",
        "readerModel": "RFID-RDR-V3.2",
        "reason": reason,
    }

    # 6. Lưu vào RAM cache
    access_logs.insert(0, log_entry)
    if len(access_logs) > MAX_LOG_SIZE:
        access_logs.pop()

    # 7. Lưu vào DB (async)
    if database.is_connected:
        await log_queue.put(log_entry)
    else:
        logger.warning("Database chưa sẵn sàng, log chỉ lưu RAM")

    # 8. Publish MQTT
    if PUBLISH_ENABLED:
        result = mqtt_client.publish(
            OUTPUT_TOPIC,
            payload=json.dumps(output, ensure_ascii=False),
            qos=1
        )
        if result.rc == mqtt.MQTT_ERR_SUCCESS:
            logger.info(f"Published {access_result} - UID {uid}")
        else:
            logger.error(f"Publish failed, rc={result.rc}")

    logger.debug(f"Output: {json.dumps(output, indent=2, ensure_ascii=False)}")

# ==================== DB WORKER ====================
async def log_worker():
    while True:
        log_entry = await log_queue.get()
        try:
            query = access_log_table.insert().values(**log_entry)
            await database.execute(query)
        except Exception as e:
            logger.exception(f"DB insert error: {e}")
        finally:
            log_queue.task_done()

# ==================== MQTT CALLBACKS ====================
mqtt_client = None
loop = None

def on_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
        logger.info("MQTT connected")
        client.subscribe(INPUT_TOPIC, qos=1)
        logger.info(f"Subscribed to {INPUT_TOPIC}")
    else:
        logger.error(f"MQTT connection failed, rc={reason_code}")

def on_message(client, userdata, msg):
    logger.info(f"Received message on {msg.topic}")
    try:
        raw_payload = json.loads(msg.payload.decode("utf-8"))
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON: {e}")
        return

    future = asyncio.run_coroutine_threadsafe(process_swipe(raw_payload), loop)
    try:
        future.result(timeout=CORE_REQUEST_TIMEOUT + 2.0)
    except Exception as e:
        logger.error(f"Processing error: {e}")

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
    timestamp: datetime
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

class AccessCheckRequest(BaseModel):
    cardId: str
    gateId: str
    direction: str
    timestamp: str

class AccessCheckResponse(BaseModel):
    allowed: bool
    reason: str
    student_id: Optional[str] = None
    full_name: Optional[str] = None
    class_name: Optional[str] = None
    cardId: str

# ==================== FASTAPI APP ====================
@asynccontextmanager
async def lifespan(app: FastAPI):
    global loop
    loop = asyncio.get_running_loop()

    await database.connect()
    logger.info("Database connected")

    worker_task = asyncio.create_task(log_worker())

    mqtt_thread = threading.Thread(target=run_mqtt, daemon=True)
    mqtt_thread.start()

    yield

    worker_task.cancel()
    await database.disconnect()
    if mqtt_client:
        mqtt_client.disconnect()
        mqtt_client.loop_stop()

app = FastAPI(
    title="Access Gate Service",
    version="1.1.0",
    description="Smart Campus Access Gate - MQTT + REST API + PostgreSQL + Core integration",
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
    uid = card_to_uid.get(cardId)
    if uid is None:
        raise HTTPException(status_code=404, detail="Card not found")
    info = whitelist.get(uid)
    if info is None:
        raise HTTPException(status_code=404, detail="Card not found")
    return CardDetail(
        cardId=cardId,
        holderName=info["full_name"],
        holderRole="STUDENT" if info["student_id"] else "GUEST",
        status="ACTIVE",
        issuedAt="2025-09-01T08:00:00Z",
        expiresAt="2029-09-01T17:00:00Z"
    )

@app.post("/access/check", response_model=AccessCheckResponse, tags=["core-integration"])
async def check_access(request: AccessCheckRequest):
    """
    Endpoint dành cho Core Business gọi để kiểm tra quyền (dùng whitelist nội bộ).
    Không gọi Core để tránh vòng lặp.
    """
    uid = card_to_uid.get(request.cardId)
    if uid is None:
        return AccessCheckResponse(
            allowed=False,
            reason="card_not_found",
            student_id=None,
            full_name=None,
            class_name=None,
            cardId=request.cardId
        )
    info = whitelist.get(uid)
    if info is None:
        return AccessCheckResponse(
            allowed=False,
            reason="uid_not_in_whitelist",
            student_id=None,
            full_name=None,
            class_name=None,
            cardId=request.cardId
        )
    return AccessCheckResponse(
        allowed=True,
        reason="uid_matched",
        student_id=info["student_id"],
        full_name=info["full_name"],
        class_name=info["class_name"],
        cardId=request.cardId
    )

def run_api():
    uvicorn.run(app, host=API_HOST, port=API_PORT)

def main():
    load_whitelist(WHITELIST_CSV)
    if not whitelist:
        logger.warning("Whitelist rỗng, mọi UID sẽ bị từ chối!")
    run_api()

if __name__ == "__main__":
    main()