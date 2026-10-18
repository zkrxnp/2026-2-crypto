/*
 * E2EE 암호 모듈
 *
 * Web Crypto API만 사용하며 DOM, WebSocket에 의존하지 않는다.
 * 브라우저에서는 전역 E2EECrypto로, Node(테스트)에서는 require()로 쓴다.
 *
 *   키 쌍     ECDH P-256, 접속마다 새로 생성, 개인키는 extractable=false
 *   공개키    raw(65바이트, 0x04||X||Y) -> base64
 *   키 파생   ECDH 공유 비밀 -> HKDF-SHA256 -> 방향별 AES-256-GCM 키 2개
 *   메시지    AES-256-GCM, 96비트 랜덤 IV, 128비트 태그(암호문 뒤에 붙음)
 *   AAD       "e2ee-chat/v1|msg|<보낸 ID>|<받는 ID>|<seq>"
 *
 * 정확한 바이트 정의는 docs/client-design.md 5장 참고.
 */
(function (root) {
  'use strict';

  const subtle = root.crypto && root.crypto.subtle;

  const PROTOCOL = 'e2ee-chat/v1';
  const CURVE = 'P-256';
  const PUBKEY_BYTES = 65;      // 0x04 || X(32) || Y(32)
  const IV_BYTES = 12;          // AES-GCM 권장 96비트
  const TAG_BYTES = 16;         // 128비트 인증 태그
  const MAX_TEXT_LENGTH = 2000; // 서버 암호문 상한(64KB)보다 충분히 작게

  const utf8 = new TextEncoder();
  const utf8Strict = new TextDecoder('utf-8', { fatal: true });

  // ------------------------------------------------------------------------
  // 오류
  // ------------------------------------------------------------------------

  /**
   * code:
   *   UNAVAILABLE  Web Crypto 사용 불가 (secure context 아님)
   *   BAD_KEY      공개키 형식/곡선 위의 점이 아님
   *   BAD_PAYLOAD  봉투 형식 오류 (IV 길이, seq 등)
   *   AUTH_FAILED  AES-GCM 인증 실패 (변조 또는 키 불일치)
   *   BAD_PLAINTEXT 인증은 통과했으나 평문 구조가 약속과 다름
   */
  class CryptoError extends Error {
    constructor(code, message) {
      super(message);
      this.name = 'CryptoError';
      this.code = code;
    }
  }

  function requireSubtle() {
    if (!subtle) {
      throw new CryptoError('UNAVAILABLE',
        'Web Crypto API를 사용할 수 없습니다. HTTPS, localhost 또는 파일로 열어야 합니다.');
    }
  }

  function isAvailable() {
    return !!subtle && root.isSecureContext !== false;
  }

  // ------------------------------------------------------------------------
  // 인코딩 헬퍼
  // ------------------------------------------------------------------------

  function b64encode(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  /** base64와 base64url을 모두 받는다 (서버도 둘 다 허용). */
  function b64decode(str) {
    if (typeof str !== 'string' || !/^[A-Za-z0-9+/_-]*={0,2}$/.test(str)) {
      throw new CryptoError('BAD_PAYLOAD', 'base64 형식이 아닙니다');
    }
    let s = str.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4 !== 0) s += '=';
    let bin;
    try {
      bin = atob(s);
    } catch (e) {
      throw new CryptoError('BAD_PAYLOAD', 'base64 디코딩 실패');
    }
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function concatBytes(...parts) {
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) {
      out.set(p, off);
      off += p.length;
    }
    return out;
  }

  function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }

  async function sha256(bytes) {
    return new Uint8Array(await subtle.digest('SHA-256', bytes));
  }

  // ------------------------------------------------------------------------
  // 키 쌍 / 공개키
  // ------------------------------------------------------------------------

  /** 개인키는 extractable=false 이므로 exportKey 자체가 거부된다. */
  async function generateKeyPair() {
    requireSubtle();
    return subtle.generateKey({ name: 'ECDH', namedCurve: CURVE }, false, ['deriveBits']);
  }

  async function exportPublicKey(publicKey) {
    return new Uint8Array(await subtle.exportKey('raw', publicKey));
  }

  /** 길이·접두 바이트를 먼저 보고, 곡선 위의 점인지는 importKey가 검사한다. */
  async function importPublicKey(raw) {
    requireSubtle();
    if (!(raw instanceof Uint8Array) || raw.length !== PUBKEY_BYTES || raw[0] !== 0x04) {
      throw new CryptoError('BAD_KEY', '공개키는 65바이트 비압축 P-256 점이어야 합니다');
    }
    try {
      return await subtle.importKey('raw', raw, { name: 'ECDH', namedCurve: CURVE }, true, []);
    } catch (e) {
      throw new CryptoError('BAD_KEY', '공개키가 P-256 곡선 위의 점이 아닙니다');
    }
  }

  // ------------------------------------------------------------------------
  // 세션 키 파생
  // ------------------------------------------------------------------------

  function keyInfo(loId, hiId, label) {
    return utf8.encode(`${PROTOCOL}|key|${loId}|${hiId}|${label}`);
  }

  async function hkdfAesKey(ikm, salt, info, usages) {
    return subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info },
      ikm,
      { name: 'AES-GCM', length: 256 },
      false,
      usages,
    );
  }

  /** 5자리 숫자 6묶음. 양쪽이 같은 값을 보면 중간에서 키가 바뀌지 않은 것. */
  async function safetyNumber(loId, loPub, hiId, hiPub) {
    const digest = await sha256(concatBytes(
      utf8.encode(`${PROTOCOL}|fp|${loId}|${hiId}|`), loPub, hiPub,
    ));
    const groups = [];
    for (let g = 0; g < 6; g++) {
      let v = 0;
      for (let i = 0; i < 5; i++) v = v * 256 + digest[g * 5 + i];
      groups.push(String(v % 100000).padStart(5, '0'));
    }
    return groups.join(' ');
  }

  /**
   * 내 개인키와 상대 공개키로 이 상대 전용 세션을 만든다.
   *
   * 랜덤 salt를 상대에게 보낼 통로가 서버에 없으므로, 양쪽이 이미 아는
   * 두 공개키의 해시를 salt로 쓰고 두 ID와 방향을 info에 넣는다.
   * 키 쌍이 접속마다 새로 만들어지므로 재접속하면 세션 키도 전부 바뀐다.
   */
  async function deriveSession({ myId, myPrivateKey, myPublicRaw, peerId, peerPublicRaw }) {
    requireSubtle();
    if (typeof myId !== 'string' || typeof peerId !== 'string' || !myId || !peerId) {
      throw new CryptoError('BAD_KEY', 'ID가 필요합니다');
    }
    if (myId === peerId) throw new CryptoError('BAD_KEY', '자기 자신과는 세션을 만들 수 없습니다');
    if (bytesEqual(myPublicRaw, peerPublicRaw)) {
      throw new CryptoError('BAD_KEY', '상대 공개키가 내 공개키와 같습니다');
    }

    const peerKey = await importPublicKey(peerPublicRaw);
    const shared = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: peerKey }, myPrivateKey, 256));

    // 정렬 기준: JS 문자열 비교(UTF-16 코드 단위). 서버가 ASCII와 한글 음절만
    // 허용하므로 유니코드 코드포인트 순서와 같다.
    const iAmLo = myId < peerId;
    const loId = iAmLo ? myId : peerId;
    const hiId = iAmLo ? peerId : myId;
    const loPub = iAmLo ? myPublicRaw : peerPublicRaw;
    const hiPub = iAmLo ? peerPublicRaw : myPublicRaw;

    const salt = await sha256(concatBytes(loPub, hiPub));
    const ikm = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
    shared.fill(0);

    // 보내는 키는 encrypt만, 받는 키는 decrypt만 가능하게 만들어 방향이 섞일 수 없다.
    const sendLabel = iAmLo ? 'lo->hi' : 'hi->lo';
    const recvLabel = iAmLo ? 'hi->lo' : 'lo->hi';
    const sendKey = await hkdfAesKey(ikm, salt, keyInfo(loId, hiId, sendLabel), ['encrypt']);
    const recvKey = await hkdfAesKey(ikm, salt, keyInfo(loId, hiId, recvLabel), ['decrypt']);

    return Object.freeze({
      myId,
      peerId,
      sendKey,
      recvKey,
      safetyNumber: await safetyNumber(loId, loPub, hiId, hiPub),
    });
  }

  // ------------------------------------------------------------------------
  // 메시지 암호화 / 복호화
  // ------------------------------------------------------------------------

  function buildAad(fromId, toId, seq) {
    return utf8.encode(`${PROTOCOL}|msg|${fromId}|${toId}|${seq}`);
  }

  function checkSeq(seq) {
    if (!Number.isSafeInteger(seq) || seq < 0) {
      throw new CryptoError('BAD_PAYLOAD', 'seq는 0 이상의 정수여야 합니다');
    }
  }

  /**
   * 평문 {text, sent_at}을 JSON으로 만들어 암호화한다.
   * 반환값은 서버 relay payload에 그대로 들어가는 {ciphertext, iv, seq}.
   */
  async function encryptMessage(session, seq, text, sentAt) {
    requireSubtle();
    checkSeq(seq);
    if (typeof text !== 'string' || text.length === 0 || text.length > MAX_TEXT_LENGTH) {
      throw new CryptoError('BAD_PLAINTEXT', `메시지는 1~${MAX_TEXT_LENGTH}자여야 합니다`);
    }
    const iv = root.crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const plaintext = utf8.encode(JSON.stringify({ text, sent_at: sentAt }));
    const ciphertext = await subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: buildAad(session.myId, session.peerId, seq), tagLength: TAG_BYTES * 8 },
      session.sendKey,
      plaintext,
    );
    return { ciphertext: b64encode(new Uint8Array(ciphertext)), iv: b64encode(iv), seq };
  }

  /** 인증에 성공한 경우에만 {text, sent_at}을 돌려준다. 실패하면 CryptoError. */
  async function decryptMessage(session, payload) {
    requireSubtle();
    if (!payload || typeof payload !== 'object') {
      throw new CryptoError('BAD_PAYLOAD', 'payload가 객체가 아닙니다');
    }
    checkSeq(payload.seq);
    const iv = b64decode(payload.iv);
    const ciphertext = b64decode(payload.ciphertext);
    if (iv.length !== IV_BYTES) throw new CryptoError('BAD_PAYLOAD', `IV는 ${IV_BYTES}바이트여야 합니다`);
    if (ciphertext.length <= TAG_BYTES) throw new CryptoError('BAD_PAYLOAD', '암호문이 너무 짧습니다');

    let plaintext;
    try {
      plaintext = await subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: buildAad(session.peerId, session.myId, payload.seq), tagLength: TAG_BYTES * 8 },
        session.recvKey,
        ciphertext,
      );
    } catch (e) {
      throw new CryptoError('AUTH_FAILED', '인증 태그 검증 실패 (변조되었거나 키가 다릅니다)');
    }

    let obj;
    try {
      obj = JSON.parse(utf8Strict.decode(plaintext));
    } catch (e) {
      throw new CryptoError('BAD_PLAINTEXT', '복호화된 평문이 약속된 형식이 아닙니다');
    }
    if (!obj || typeof obj.text !== 'string' || typeof obj.sent_at !== 'number') {
      throw new CryptoError('BAD_PLAINTEXT', '복호화된 평문이 약속된 형식이 아닙니다');
    }
    return { text: obj.text, sent_at: obj.sent_at };
  }

  const E2EECrypto = Object.freeze({
    PROTOCOL,
    IV_BYTES,
    TAG_BYTES,
    MAX_TEXT_LENGTH,
    CryptoError,
    isAvailable,
    b64encode,
    b64decode,
    generateKeyPair,
    exportPublicKey,
    importPublicKey,
    deriveSession,
    encryptMessage,
    decryptMessage,
  });

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = E2EECrypto;
  } else {
    root.E2EECrypto = E2EECrypto;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
