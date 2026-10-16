from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse

# --------------------------------------------------------------------------
# 설정
# --------------------------------------------------------------------------

MAX_FRAME_BYTES = 128 * 1024        # WebSocket 프레임 상한
MAX_PUBKEY_LEN = 512                # base64 공개키 길이 상한 (P-256 raw = 88자)
MAX_CIPHERTEXT_LEN = 64 * 1024      # base64 암호문 길이 상한
MAX_IV_LEN = 64                     # base64 IV 길이 상한 (12바이트 -> 16자)

NICK_RE = re.compile(r"^[A-Za-z0-9_\-가-힣]{2,20}$")
B64_RE = re.compile(r"^[A-Za-z0-9+/_\-]+={0,2}$")   # base64 / base64url 모두 허용

# relay 봉투에서 허용되는 필드. 이 집합 밖의 키가 하나라도 있으면 거부한다.
ENVELOPE_REQUIRED = {"ciphertext", "iv"}
ENVELOPE_OPTIONAL = {"seq"}
ENVELOPE_ALLOWED = ENVELOPE_REQUIRED | ENVELOPE_OPTIONAL

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-5s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("e2ee-relay")


# --------------------------------------------------------------------------
# 접속 관리
# --------------------------------------------------------------------------

@dataclass
class Client:
    ws: WebSocket
    cid: str
    pubkey: str                       # base64 (서버는 '전달'만 하고 쓰지 않는다)
    joined_at: float = field(default_factory=time.time)
    # 여러 코루틴이 같은 소켓에 동시에 send 하는 것을 막는다
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class Hub:
    """접속 중인 클라이언트 테이블. 메시지는 절대 보관하지 않는다."""

    def __init__(self) -> None:
        self._clients: dict[str, Client] = {}

    # --- 등록 / 해제 ---------------------------------------------------

    def add(self, client: Client) -> None:
        self._clients[client.cid] = client

    def remove(self, cid: str) -> None:
        self._clients.pop(cid, None)

    def get(self, cid: str) -> Client | None:
        return self._clients.get(cid)

    def exists(self, cid: str) -> bool:
        return cid in self._clients

    def roster(self, exclude: str | None = None) -> list[dict[str, str]]:
        return [
            {"id": c.cid, "pubkey": c.pubkey}
            for c in self._clients.values()
            if c.cid != exclude
        ]

    # --- 전송 -----------------------------------------------------------

    async def send(self, cid: str, obj: dict[str, Any]) -> bool:
        client = self._clients.get(cid)
        if client is None:
            return False
        try:
            async with client.lock:
                await client.ws.send_text(json.dumps(obj, ensure_ascii=False))
            return True
        except Exception:
            return False

    async def broadcast(self, obj: dict[str, Any], exclude: str | None = None) -> None:
        targets = [c.cid for c in self._clients.values() if c.cid != exclude]
        for cid in targets:
            await self.send(cid, obj)


hub = Hub()
app = FastAPI(title="E2EE Chat Relay", version="1.0")


# --------------------------------------------------------------------------
# 검증 헬퍼
# --------------------------------------------------------------------------

class ProtocolError(Exception):
    """프로토콜 위반. 사유를 클라이언트에 돌려준다."""


def want_b64(value: Any, field_name: str, max_len: int) -> str:
    if not isinstance(value, str) or not value:
        raise ProtocolError(f"{field_name}: 문자열이어야 합니다")
    if len(value) > max_len:
        raise ProtocolError(f"{field_name}: 너무 깁니다 (>{max_len})")
    if not B64_RE.match(value):
        raise ProtocolError(f"{field_name}: base64 형식이 아닙니다")
    return value


def validate_envelope(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ProtocolError("payload: 객체여야 합니다")

    keys = set(payload.keys())
    unknown = keys - ENVELOPE_ALLOWED
    if unknown:
        raise ProtocolError(
            f"허용되지 않은 필드: {sorted(unknown)} "
            f"(이 서버는 {sorted(ENVELOPE_ALLOWED)} 외에는 중계하지 않습니다)"
        )
    missing = ENVELOPE_REQUIRED - keys
    if missing:
        raise ProtocolError(f"필수 필드 누락: {sorted(missing)}")

    envelope: dict[str, Any] = {
        "ciphertext": want_b64(payload["ciphertext"], "ciphertext", MAX_CIPHERTEXT_LEN),
        "iv": want_b64(payload["iv"], "iv", MAX_IV_LEN),
    }
    if "seq" in payload:
        seq = payload["seq"]
        if not isinstance(seq, int) or seq < 0:
            raise ProtocolError("seq: 0 이상의 정수여야 합니다")
        envelope["seq"] = seq
    return envelope


def preview(b64: str, n: int = 32) -> str:
    """로그용 암호문 미리보기 (평문이 아님을 눈으로 확인시키는 용도)."""
    return b64[:n] + ("…" if len(b64) > n else "")


# --------------------------------------------------------------------------
# WebSocket 엔드포인트
# --------------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    await ws.accept()
    client: Client | None = None

    try:
        # 1) 첫 프레임은 반드시 register
        client = await handle_registration(ws)
        if client is None:
            return

        # 2) 메인 루프
        while True:
            raw = await ws.receive_text()
            if len(raw) > MAX_FRAME_BYTES:
                await reject(ws, "frame too large")
                continue
            try:
                msg = json.loads(raw)
                if not isinstance(msg, dict):
                    raise ProtocolError("JSON 객체가 아닙니다")
                await dispatch(client, msg)
            except json.JSONDecodeError:
                await reject(ws, "JSON 파싱 실패")
            except ProtocolError as e:
                await reject(ws, str(e))

    except WebSocketDisconnect:
        pass
    except Exception as e:  # noqa: BLE001
        log.warning("unexpected error: %s", type(e).__name__)
    finally:
        if client is not None:
            hub.remove(client.cid)
            log.info("LEAVE  id=%s  (online=%d)", client.cid, len(hub.roster()))
            await hub.broadcast({"type": "peer_offline", "id": client.cid})


async def handle_registration(ws: WebSocket) -> Client | None:
    """최초 등록: 닉네임 + 공개키를 받는다."""
    try:
        first = json.loads(await ws.receive_text())
    except (json.JSONDecodeError, WebSocketDisconnect):
        await ws.close(code=4000, reason="register 실패")
        return None

    if not isinstance(first, dict) or first.get("type") != "register":
        await ws.close(code=4000, reason="첫 메시지는 register 여야 합니다")
        return None

    cid = first.get("id")
    if not isinstance(cid, str) or not NICK_RE.match(cid):
        await ws.close(code=4001, reason="잘못된 ID 형식")
        return None
    if hub.exists(cid):
        await ws.close(code=4002, reason="이미 사용 중인 ID")
        return None

    try:
        pubkey = want_b64(first.get("pubkey"), "pubkey", MAX_PUBKEY_LEN)
    except ProtocolError as e:
        await ws.close(code=4003, reason=str(e))
        return None

    client = Client(ws=ws, cid=cid, pubkey=pubkey)
    hub.add(client)

    # 본인에게: 등록 완료 + 현재 접속자 명단(공개키 포함)
    await hub.send(cid, {
        "type": "registered",
        "id": cid,
        "users": hub.roster(exclude=cid),
    })
    # 나머지에게: 새 피어 등장 (공개키 배포 -> ECDH 준비)
    await hub.broadcast(
        {"type": "peer_online", "id": cid, "pubkey": pubkey},
        exclude=cid,
    )

    log.info("JOIN   id=%s  pubkey=%s  (online=%d)",
             cid, preview(pubkey, 24), len(hub.roster()))
    return client


async def dispatch(client: Client, msg: dict[str, Any]) -> None:
    mtype = msg.get("type")

    if mtype == "relay":
        await handle_relay(client, msg)

    elif mtype == "list":
        await hub.send(client.cid, {"type": "users", "users": hub.roster(exclude=client.cid)})

    elif mtype == "get_pubkey":
        target = msg.get("target")
        peer = hub.get(target) if isinstance(target, str) else None
        if peer is None:
            raise ProtocolError(f"'{target}' 님은 접속 중이 아닙니다")
        await hub.send(client.cid, {"type": "pubkey", "id": peer.cid, "pubkey": peer.pubkey})

    elif mtype == "ping":
        await hub.send(client.cid, {"type": "pong", "t": int(time.time() * 1000)})

    else:
        raise ProtocolError(f"알 수 없는 type: {mtype!r}")


async def handle_relay(client: Client, msg: dict[str, Any]) -> None:
    """암호문 중계 — 서버가 하는 일의 전부."""
    to = msg.get("to")
    if not isinstance(to, str) or not hub.exists(to):
        raise ProtocolError(f"'{to}' 님은 접속 중이 아닙니다")
    if to == client.cid:
        raise ProtocolError("자기 자신에게는 보낼 수 없습니다")

    envelope = validate_envelope(msg.get("payload"))

    delivered = await hub.send(to, {
        "type": "message",
        "from": client.cid,
        "payload": envelope,          # 받은 그대로, 손대지 않고 전달
        "ts": int(time.time() * 1000),
    })

    # 로그: 메타데이터 + 암호문 미리보기만. 평문은 애초에 서버에 도달하지 않는다.
    log.info(
        "RELAY  %s -> %s  bytes=%d  iv=%s  ct=%s",
        client.cid, to, len(envelope["ciphertext"]),
        envelope["iv"], preview(envelope["ciphertext"]),
    )

    await hub.send(client.cid, {
        "type": "ack",
        "to": to,
        "seq": envelope.get("seq"),
        "delivered": delivered,
    })


async def reject(ws: WebSocket, reason: str) -> None:
    log.warning("REJECT %s", reason)
    try:
        await ws.send_text(json.dumps({"type": "error", "reason": reason}, ensure_ascii=False))
    except Exception:
        pass


# --------------------------------------------------------------------------
# 부가 HTTP 엔드포인트
# --------------------------------------------------------------------------

@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({"status": "ok", "online": len(hub.roster())})


@app.get("/users")
async def users() -> JSONResponse:
    """서버가 보관 중인 전부 = ID와 공개키. 평문도, 개인키도, 메시지도 없다."""
    return JSONResponse({"users": hub.roster()})


@app.get("/")
async def index():
    page = Path(__file__).with_name("test_client.html")
    if page.exists():
        return FileResponse(page)
    return JSONResponse({"service": "E2EE Chat Relay", "ws": "/ws"})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
