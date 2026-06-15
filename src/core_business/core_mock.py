#!/usr/bin/env python3
"""
Mock Core Business Service - chỉ để test tích hợp với Access Gate.
Implement POST /access/check và GET /health.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime, timezone
import uuid
import uvicorn

app = FastAPI(title="Core Business Mock")

# --- Models (giống với OpenAPI, chỉ lấy các trường cần thiết) ---
class AccessCheckRequest(BaseModel):
    requestId: str
    cardId: str
    gateId: str
    direction: str
    timestamp: str

class AccessCheckResponse(BaseModel):
    decisionId: str
    allow: bool
    reasonCode: str
    policyId: str | None = None
    expiresAt: str | None = None

# --- Endpoints ---
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "core-business-mock",
        "time": datetime.now(timezone.utc).isoformat()
    }

@app.post("/access/check", response_model=AccessCheckResponse)
async def check_access(request: AccessCheckRequest):
    # Log request để theo dõi
    print(f"[Mock Core] Received: {request.dict()}")

    # Logic đơn giản: cho phép nếu cardId có đuôi '01'..'10' hoặc 'UNKNOWN' (tùy ý)
    # Bạn có thể chỉnh sửa để luôn allow hoặc deny theo ý muốn test.
    card_suffix = request.cardId[-2:] if len(request.cardId) >= 2 else ""
    if card_suffix in ["01", "02", "03", "04", "05", "06", "07", "08", "09", "10"]:
        allow = True
        reason = "ALLOWED"
        policy = "POL-101"
    else:
        allow = False
        reason = "CARD_EXPIRED"
        policy = None

    response = AccessCheckResponse(
        decisionId=str(uuid.uuid4()),
        allow=allow,
        reasonCode=reason,
        policyId=policy,
        expiresAt=datetime.now(timezone.utc).isoformat() if allow else None
    )
    print(f"[Mock Core] Response: {response.dict()}")
    return response

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9000)