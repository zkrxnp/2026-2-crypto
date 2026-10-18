"""client/crypto.js 교차 검증.

docs/client-design.md 5장의 키 파생·암호화 규칙을 Python cryptography로 따로 구현하고,
JS가 만든 암호문을 Python이 풀고 Python이 만든 암호문을 JS가 푸는지 확인한다.
양쪽이 맞으면 JS 구현이 문서에 적힌 규칙대로 동작한다는 독립적인 증거가 된다.

실행: pytest tests/test_client_crosscheck.py   (node 필요)
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HELPER = Path(__file__).parent / "client" / "node_helper.js"
PROTOCOL = "e2ee-chat/v1"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node가 필요합니다")


# --------------------------------------------------------------------------
# 문서 규칙의 독립 구현
# --------------------------------------------------------------------------

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(text: str) -> bytes:
    return base64.b64decode(text)


class User:
    def __init__(self, uid: str) -> None:
        self.id = uid
        self.priv = ec.generate_private_key(ec.SECP256R1())
        self.pub = self.priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        self.pkcs8 = self.priv.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


def ordered(me: User, peer: User) -> tuple[User, User]:
    return (me, peer) if me.id < peer.id else (peer, me)


def direction_key(me: User, peer: User, sender: User) -> bytes:
    lo, hi = ordered(me, peer)
    peer_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer.pub)
    shared = me.priv.exchange(ec.ECDH(), peer_key)
    label = "lo->hi" if sender is lo else "hi->lo"
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(lo.pub + hi.pub).digest(),
        info=f"{PROTOCOL}|key|{lo.id}|{hi.id}|{label}".encode(),
    ).derive(shared)


def safety_number(a: User, b: User) -> str:
    lo, hi = ordered(a, b)
    digest = hashlib.sha256(f"{PROTOCOL}|fp|{lo.id}|{hi.id}|".encode() + lo.pub + hi.pub).digest()
    groups = [int.from_bytes(digest[g * 5:(g + 1) * 5], "big") % 100000 for g in range(6)]
    return " ".join(f"{v:05d}" for v in groups)


def aad(sender: str, recipient: str, seq: int) -> bytes:
    return f"{PROTOCOL}|msg|{sender}|{recipient}|{seq}".encode()


def run_js(me: User, peer: User, **op) -> dict:
    req = {
        "myId": me.id,
        "myPkcs8": b64(me.pkcs8),
        "myPub": b64(me.pub),
        "peerId": peer.id,
        "peerPub": b64(peer.pub),
        **op,
    }
    out = subprocess.run(
        ["node", str(HELPER)], input=json.dumps(req), capture_output=True, text=True, check=True
    )
    return json.loads(out.stdout)


# --------------------------------------------------------------------------
# 테스트
# --------------------------------------------------------------------------

@pytest.mark.parametrize("ids", [("alice", "bob"), ("철수", "alice"), ("user_2", "user-1")])
def test_js_encrypts_python_decrypts(ids):
    alice, bob = User(ids[0]), User(ids[1])
    out = run_js(alice, bob, encrypt={"seq": 7, "text": "안녕하세요 E2EE", "sentAt": 1234})
    payload = out["payload"]

    assert out["safetyNumber"] == safety_number(alice, bob)
    assert payload["seq"] == 7
    assert len(unb64(payload["iv"])) == 12

    key = direction_key(bob, alice, sender=alice)
    plaintext = AESGCM(key).decrypt(unb64(payload["iv"]), unb64(payload["ciphertext"]), aad(alice.id, bob.id, 7))
    assert json.loads(plaintext) == {"text": "안녕하세요 E2EE", "sent_at": 1234}


@pytest.mark.parametrize("ids", [("alice", "bob"), ("bob", "alice"), ("한글닉", "zz")])
def test_python_encrypts_js_decrypts(ids):
    alice, bob = User(ids[0]), User(ids[1])
    key = direction_key(bob, alice, sender=bob)
    iv = os.urandom(12)
    body = json.dumps({"text": "답장입니다", "sent_at": 99}, ensure_ascii=False).encode()
    ct = AESGCM(key).encrypt(iv, body, aad(bob.id, alice.id, 3))

    out = run_js(alice, bob, decrypt={"ciphertext": b64(ct), "iv": b64(iv), "seq": 3})
    assert out.get("plaintext") == {"text": "답장입니다", "sent_at": 99}


def test_wrong_direction_key_is_rejected_by_js():
    alice, bob = User("alice"), User("bob")
    # bob이 보내는 메시지를 alice->bob 방향 키로 암호화하면 alice는 풀 수 없어야 한다
    wrong_key = direction_key(bob, alice, sender=alice)
    iv = os.urandom(12)
    body = json.dumps({"text": "x", "sent_at": 1}).encode()
    ct = AESGCM(wrong_key).encrypt(iv, body, aad(bob.id, alice.id, 0))

    out = run_js(alice, bob, decrypt={"ciphertext": b64(ct), "iv": b64(iv), "seq": 0})
    assert out.get("error") == "AUTH_FAILED"
