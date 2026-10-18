"""브라우저 E2E 테스트: 실제 server.py + 헤드리스 Chromium 창 여러 개.

client/index.html을 파일로 열어 접속하고, 브라우저가 실제로 주고받은 WebSocket 프레임과
서버 로그에서 평문이 보이지 않는지, 변조·재전송·재접속을 클라이언트가 올바르게 처리하는지 본다.

실행:
  pip install pytest playwright && playwright install chromium
  pytest tests/test_client_e2e.py
  (이미 설치된 Chromium을 쓰려면 CHROMIUM_PATH=/경로/chrome 지정)
"""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

playwright_api = pytest.importorskip("playwright.sync_api")
expect = playwright_api.expect

ROOT = Path(__file__).resolve().parent.parent
CLIENT_URL = (ROOT / "client" / "index.html").as_uri()


# --------------------------------------------------------------------------
# 픽스처
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def server(tmp_path_factory):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    log_path = tmp_path_factory.mktemp("server") / "server.log"
    log_file = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "server:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, stdout=log_file, stderr=subprocess.STDOUT,
    )
    deadline = time.time() + 15
    while True:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1)
            break
        except OSError:
            if time.time() > deadline or proc.poll() is not None:
                proc.kill()
                raise RuntimeError("서버가 뜨지 않았습니다: " + log_path.read_text(encoding="utf-8"))
            time.sleep(0.2)

    yield {"ws": f"ws://127.0.0.1:{port}/ws", "log": log_path}

    proc.terminate()
    proc.wait(timeout=10)
    log_file.close()


@pytest.fixture(scope="module")
def browser():
    with playwright_api.sync_playwright() as p:
        b = p.chromium.launch(executable_path=os.environ.get("CHROMIUM_PATH") or None)
        yield b
        b.close()


class Client:
    """브라우저 창 하나 = 사용자 한 명. 오간 WebSocket 프레임과 페이지 오류를 모은다."""

    def __init__(self, browser, server, nickname, expect_ok=True):
        self.context = browser.new_context()
        self.page = self.context.new_page()
        self.frames: list[str] = []
        self.errors: list[str] = []
        self.page.on("websocket", self._watch)
        self.page.on("pageerror", lambda e: self.errors.append(str(e)))
        self.page.on("console", lambda m: m.type == "error" and self.errors.append(m.text))

        self.page.goto(CLIENT_URL)
        self.page.fill("#nickname", nickname)
        self.page.fill("#server-url", server["ws"])
        self.page.click("#login-button")
        if expect_ok:
            expect(self.page.locator("#chat-view")).to_be_visible()

    def _watch(self, ws):
        ws.on("framesent", lambda payload: self.frames.append(str(payload)))
        ws.on("framereceived", lambda payload: self.frames.append(str(payload)))

    def open_chat(self, peer):
        self.page.click(f'.peer[data-peer="{peer}"]')
        expect(self.page.locator("#conv-state")).to_have_text("종단간 암호화")

    def open_tools(self):
        self.page.locator("#tools").evaluate("d => { d.open = true; }")

    def send(self, text, tamper=None):
        if tamper:
            self.open_tools()
            self.page.select_option("#tamper-mode", tamper)
        self.page.fill("#message-input", text)
        self.page.press("#message-input", "Enter")

    def received(self):
        return self.page.locator(".entry.in .text")

    def close(self):
        self.context.close()


# --------------------------------------------------------------------------
# 테스트
# --------------------------------------------------------------------------

def test_chat_roundtrip_without_plaintext_on_wire_or_in_log(server, browser):
    secret1 = "비밀메시지-PLAINTEXT-7f3a"
    secret2 = "답장도-비밀-PLAINTEXT-91c0"
    alice = Client(browser, server, "alice")
    bob = Client(browser, server, "bob")

    alice.open_chat("bob")
    alice.send(secret1)
    expect(alice.page.locator(".entry.out .meta").last).to_contain_text("전달됨")

    # bob은 아직 대화를 열지 않았으므로 안 읽은 표시가 뜨고, 받는 순간 키를 파생해 복호화한다
    expect(bob.page.locator('.peer[data-peer="alice"] .unread')).to_have_text("1")
    bob.open_chat("alice")
    expect(bob.received()).to_have_text([secret1])

    bob.send(secret2)
    expect(alice.received()).to_have_text([secret2])

    # 양쪽 안전 번호가 같다
    expect(alice.page.locator("#safety-number")).to_have_text(bob.page.locator("#safety-number").inner_text())

    # 브라우저가 실제로 주고받은 프레임: 닉네임(평문 메타데이터)은 보이지만 메시지는 안 보인다
    wire = "\n".join(alice.frames + bob.frames)
    assert '"relay"' in wire and '"ciphertext"' in wire
    assert "alice" in wire
    assert secret1 not in wire and secret2 not in wire

    # 단순 base64 인코딩 같은 가짜 암호화도 걸러내도록 암호문 필드를 풀어서도 확인한다
    ciphertexts = [
        base64.b64decode(frame["payload"]["ciphertext"])
        for frame in map(json.loads, alice.frames + bob.frames)
        if frame.get("type") in ("relay", "message")
    ]
    assert len(ciphertexts) == 4  # 두 메시지 x (보낸 쪽 relay + 받은 쪽 message)
    for ct in ciphertexts:
        assert secret1.encode() not in ct and secret2.encode() not in ct

    # 서버 로그에도 중계 기록은 있지만 평문은 없다
    log = server["log"].read_text(encoding="utf-8")
    assert "RELAY  alice -> bob" in log
    assert secret1 not in log and secret2 not in log

    assert alice.errors == [] and bob.errors == []
    alice.close()
    bob.close()


@pytest.mark.parametrize("mode", ["ciphertext", "tag", "iv", "seq"])
def test_tampered_message_is_discarded(server, browser, mode):
    a = Client(browser, server, f"ta_{mode}")
    b = Client(browser, server, f"tb_{mode}")
    a.open_chat(f"tb_{mode}")
    b.open_chat(f"ta_{mode}")

    a.send("변조될 메시지", tamper=mode)
    expect(b.page.locator(".entry.system.error")).to_contain_text("폐기했습니다")
    expect(b.received()).to_have_count(0)
    # 변조 모드는 한 번만 적용되고, 다음 정상 메시지는 그대로 도착한다
    expect(a.page.locator("#tamper-mode")).to_have_value("none")
    a.send("정상 메시지")
    expect(b.received()).to_have_text(["정상 메시지"])

    assert a.errors == [] and b.errors == []
    a.close()
    b.close()


def test_replayed_message_is_discarded(server, browser):
    a = Client(browser, server, "replay_a")
    b = Client(browser, server, "replay_b")
    a.open_chat("replay_b")
    b.open_chat("replay_a")

    a.send("한 번만 보여야 함")
    expect(b.received()).to_have_text(["한 번만 보여야 함"])
    a.open_tools()
    a.page.click("#replay-button")
    expect(b.page.locator(".entry.system.warn")).to_contain_text("재전송된 메시지를 감지")
    expect(b.received()).to_have_count(1)
    a.close()
    b.close()


def test_peer_leaves_and_rejoins_with_new_keys(server, browser):
    a = Client(browser, server, "stay")
    b = Client(browser, server, "leaver")
    a.open_chat("leaver")
    a.send("첫 세션")
    expect(b.page.locator('.peer[data-peer="stay"] .unread')).to_have_text("1")
    old_safety = a.page.locator("#safety-number").inner_text()

    b.close()
    expect(a.page.locator(".entry.system").last).to_contain_text("나갔습니다")
    expect(a.page.locator("#conv-state")).to_have_text("오프라인")
    expect(a.page.locator("#message-input")).to_be_disabled()

    b2 = Client(browser, server, "leaver")
    expect(a.page.locator(".entry.system.warn").last).to_contain_text("새 키로 대화")
    expect(a.page.locator("#conv-state")).to_have_text("종단간 암호화")
    assert a.page.locator("#safety-number").inner_text() != old_safety

    a.send("두 번째 세션")
    b2.open_chat("stay")
    expect(b2.received()).to_have_text(["두 번째 세션"])
    expect(b2.page.locator("#safety-number")).to_have_text(a.page.locator("#safety-number").inner_text())
    a.close()
    b2.close()


def test_login_errors(server, browser):
    first = Client(browser, server, "dupe")
    second = Client(browser, server, "dupe", expect_ok=False)
    expect(second.page.locator("#login-error")).to_contain_text("이미 사용 중")

    second.page.fill("#nickname", "a")
    second.page.click("#login-button")
    expect(second.page.locator("#login-error")).to_contain_text("2~20자")
    first.close()
    second.close()


def test_message_text_is_not_interpreted_as_html(server, browser):
    a = Client(browser, server, "xss_a")
    b = Client(browser, server, "xss_b")
    a.open_chat("xss_b")
    b.open_chat("xss_a")

    payload = '<img src=x onerror="document.title=\'pwned\'"><b>bold</b>'
    a.send(payload)
    expect(b.received()).to_have_text([payload])
    assert b.page.locator("#messages img, #messages b").count() == 0
    assert b.page.title() != "pwned"
    a.close()
    b.close()
