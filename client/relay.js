/*
 * WebSocket 클라이언트 (현재 server.py 프로토콜 전용)
 *
 * 서버는 한 연결에서 받은 프레임을 순서대로 처리하고, 요청 하나마다
 * 응답(ack / users / pubkey / pong / error)을 정확히 하나 돌려준다.
 * error 프레임에는 어떤 요청에 대한 응답인지 표시가 없으므로, 보낸 순서대로
 * 대기열(FIFO)에 넣어 두고 도착하는 응답과 순서대로 짝짓는다.
 *
 * 서버가 먼저 보내는 알림(peer_online / peer_offline / message)은 응답이 아니므로
 * 대기열과 무관하게 이벤트로 넘긴다. 이 모듈은 암호화를 전혀 모른다.
 */
(function (root) {
  'use strict';

  const REQUEST_TIMEOUT_MS = 10000;
  const RESPONSE_TYPES = new Set(['ack', 'users', 'pubkey', 'pong', 'error']);

  // server.py handle_registration()의 close 코드
  const CLOSE_REASONS = {
    1006: '서버에 연결할 수 없거나 연결이 끊어졌습니다',
    4000: '등록 메시지가 올바르지 않습니다',
    4001: '닉네임 형식이 올바르지 않습니다',
    4002: '이미 사용 중인 닉네임입니다',
    4003: '공개키 형식이 올바르지 않습니다',
  };

  class RelayError extends Error {
    constructor(code, message) {
      super(message);
      this.name = 'RelayError';
      this.code = code;
    }
  }

  function isObject(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
  }

  function sanitizeUsers(users) {
    if (!Array.isArray(users)) return [];
    return users.filter((u) => isObject(u) && typeof u.id === 'string' && typeof u.pubkey === 'string');
  }

  function describeClose(ev) {
    return ev.reason || CLOSE_REASONS[ev.code] || `연결이 종료되었습니다 (코드 ${ev.code})`;
  }

  class RelayClient {
    constructor() {
      this.ws = null;
      this.id = null;
      this.pending = [];
      this.handlers = {};
      this.localCloseReason = null;
    }

    /** 이벤트: peer_online, peer_offline, message, close, server_error */
    on(type, fn) {
      (this.handlers[type] = this.handlers[type] || []).push(fn);
      return this;
    }

    emit(type, data) {
      for (const fn of this.handlers[type] || []) {
        try {
          fn(data);
        } catch (e) {
          console.error(e);
        }
      }
    }

    get isOpen() {
      return !!this.ws && this.ws.readyState === WebSocket.OPEN && this.id !== null;
    }

    /**
     * 접속 후 첫 프레임으로 register를 보낸다.
     * 성공하면 registered.users(다른 접속자와 공개키)로 resolve 된다.
     * 서버가 등록을 거부하면 close 코드 4000~4003으로 끊으므로 그 사유로 reject 된다.
     */
    connect(url, id, pubkeyB64) {
      return new Promise((resolve, reject) => {
        let ws;
        try {
          ws = new WebSocket(url);
        } catch (e) {
          reject(new RelayError('BAD_URL', '서버 주소가 올바르지 않습니다'));
          return;
        }
        this.ws = ws;
        let registered = false;

        ws.onopen = () => {
          ws.send(JSON.stringify({ type: 'register', id, pubkey: pubkeyB64 }));
        };

        ws.onmessage = (ev) => {
          let msg;
          try {
            msg = JSON.parse(ev.data);
          } catch (e) {
            return;
          }
          if (!isObject(msg) || typeof msg.type !== 'string') return;

          if (!registered) {
            if (msg.type === 'registered' && msg.id === id) {
              registered = true;
              this.id = id;
              resolve({ users: sanitizeUsers(msg.users) });
            }
            return;
          }
          this.handleFrame(msg);
        };

        ws.onclose = (ev) => {
          const err = new RelayError(ev.code, this.localCloseReason || describeClose(ev));
          this.failPending(err);
          this.id = null;
          if (registered) {
            this.emit('close', { code: ev.code, reason: err.message });
          } else {
            reject(err);
          }
        };
      });
    }

    handleFrame(msg) {
      if (RESPONSE_TYPES.has(msg.type)) {
        this.handleResponse(msg);
        return;
      }
      switch (msg.type) {
        case 'peer_online':
          if (typeof msg.id === 'string' && typeof msg.pubkey === 'string') {
            this.emit('peer_online', { id: msg.id, pubkey: msg.pubkey });
          }
          break;
        case 'peer_offline':
          if (typeof msg.id === 'string') this.emit('peer_offline', { id: msg.id });
          break;
        case 'message':
          if (typeof msg.from === 'string' && isObject(msg.payload)) {
            this.emit('message', msg);
          }
          break;
        default:
          // 모르는 알림은 무시한다
          break;
      }
    }

    handleResponse(msg) {
      const entry = this.pending.shift();
      if (!entry) {
        if (msg.type === 'error') this.emit('server_error', { reason: String(msg.reason) });
        return;
      }
      clearTimeout(entry.timer);
      if (msg.type === 'error') {
        entry.reject(new RelayError('SERVER', String(msg.reason || '서버 오류')));
      } else if (msg.type === entry.expect) {
        entry.resolve(msg);
      } else {
        // 짝이 어긋났다면 이후 응답도 믿을 수 없으므로 연결을 끊는다
        entry.reject(new RelayError('DESYNC', '서버 응답 순서가 맞지 않습니다'));
        this.close('서버 응답 순서가 맞지 않아 연결을 끊었습니다');
      }
    }

    request(frame, expect) {
      return new Promise((resolve, reject) => {
        if (!this.isOpen) {
          reject(new RelayError('CLOSED', '서버에 연결되어 있지 않습니다'));
          return;
        }
        const entry = { expect, resolve, reject, timer: null };
        entry.timer = setTimeout(() => {
          this.close('서버가 응답하지 않아 연결을 끊었습니다');
        }, REQUEST_TIMEOUT_MS);
        this.pending.push(entry);
        this.ws.send(JSON.stringify(frame));
      });
    }

    failPending(err) {
      const pending = this.pending;
      this.pending = [];
      for (const entry of pending) {
        clearTimeout(entry.timer);
        entry.reject(err);
      }
    }

    /** payload = {ciphertext, iv, seq}. 응답: {type:'ack', to, seq, delivered} */
    relay(to, payload) {
      return this.request({ type: 'relay', to, payload }, 'ack');
    }

    async listUsers() {
      const res = await this.request({ type: 'list' }, 'users');
      return sanitizeUsers(res.users);
    }

    close(reason) {
      if (this.ws && this.ws.readyState <= WebSocket.OPEN) {
        this.localCloseReason = reason || '연결을 종료했습니다';
        this.ws.close(1000);
      }
    }
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { RelayClient, RelayError };
  } else {
    root.RelayClient = RelayClient;
    root.RelayError = RelayError;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
