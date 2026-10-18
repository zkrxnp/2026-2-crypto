/*
 * 클라이언트 UI / 상태 관리
 *
 * crypto.js(E2EECrypto)와 relay.js(RelayClient)를 이어 붙여 화면을 그린다.
 *  - 암호 연산은 전부 E2EECrypto에 맡기고, 여기서는 키를 직접 다루지 않는다.
 *  - 화면에 넣는 문자열은 전부 textContent로 넣는다 (상대가 보낸 값을 HTML로 해석하지 않음).
 *  - 상대별로 송신/수신 작업을 각각 한 줄로 세워(Promise 체인) seq 순서가 뒤섞이지 않게 한다.
 */
(function () {
  'use strict';

  const C = window.E2EECrypto;
  const NICK_RE = /^[A-Za-z0-9_\-가-힣]{2,20}$/; // server.py NICK_RE와 같음

  const TAMPER_LABELS = {
    ciphertext: '암호문 변조',
    tag: '인증 태그 변조',
    iv: 'IV 변조',
    seq: 'seq(AAD) 변조',
  };

  const STATUS_LABELS = {
    sending: '전송 중',
    delivered: '전달됨',
    undelivered: '상대에게 전달되지 않음',
    failed: '전송 실패',
  };

  const $ = (id) => document.getElementById(id);
  const el = {
    loginView: $('login-view'),
    loginForm: $('login-form'),
    nickname: $('nickname'),
    serverUrl: $('server-url'),
    loginButton: $('login-button'),
    loginError: $('login-error'),
    chatView: $('chat-view'),
    meName: $('me-name'),
    connDot: $('conn-dot'),
    connText: $('conn-text'),
    peerList: $('peer-list'),
    peerEmpty: $('peer-empty'),
    tamperMode: $('tamper-mode'),
    replayButton: $('replay-button'),
    myPubkey: $('my-pubkey'),
    logoutButton: $('logout-button'),
    banner: $('banner'),
    convHeader: $('conv-header'),
    convName: $('conv-name'),
    convState: $('conv-state'),
    safety: $('safety'),
    safetyNumber: $('safety-number'),
    safetyVerified: $('safety-verified'),
    placeholder: $('placeholder'),
    messages: $('messages'),
    sendForm: $('send-form'),
    messageInput: $('message-input'),
    sendButton: $('send-button'),
  };

  /** 접속 중일 때만 값이 있다. 나가거나 끊기면 키와 함께 통째로 버린다. */
  let state = null;

  function newState() {
    return { relay: null, me: null, peers: new Map(), activeId: null, connected: false };
  }

  function newPeer(id, pubB64) {
    return {
      id,
      pubB64,
      online: true,
      epoch: 0,              // 상대 공개키가 바뀔 때마다 증가
      sessionPromise: null,
      session: null,
      keyError: null,
      sendSeq: 0,            // 다음에 보낼 seq
      lastRecvSeq: -1,       // 마지막으로 인증에 성공한 수신 seq
      outbox: Promise.resolve(),
      inbox: Promise.resolve(),
      verified: false,
      lastSent: null,        // 재전송 시연용
      entries: [],
      unread: 0,
    };
  }

  /** 상대가 나가거나 새 키로 들어오면 그 상대와의 세션 키와 카운터를 버린다. */
  function resetSession(peer) {
    peer.epoch += 1;
    peer.sessionPromise = null;
    peer.session = null;
    peer.keyError = null;
    peer.sendSeq = 0;
    peer.lastRecvSeq = -1;
    peer.verified = false;
    peer.lastSent = null;
  }

  function activePeer() {
    return state && state.activeId ? state.peers.get(state.activeId) || null : null;
  }

  // ------------------------------------------------------------------------
  // 세션 키
  // ------------------------------------------------------------------------

  function getSession(peer) {
    if (!peer.sessionPromise) {
      const me = state.me;
      const epoch = peer.epoch;
      peer.sessionPromise = (async () => C.deriveSession({
        myId: me.id,
        myPrivateKey: me.keyPair.privateKey,
        myPublicRaw: me.publicRaw,
        peerId: peer.id,
        peerPublicRaw: C.b64decode(peer.pubB64),
      }))().then(
        (session) => {
          if (peer.epoch === epoch) peer.session = session;
          refreshHeader(peer);
          return session;
        },
        (err) => {
          if (peer.epoch === epoch) peer.keyError = err.message;
          refreshHeader(peer);
          throw err;
        },
      );
    }
    return peer.sessionPromise;
  }

  // ------------------------------------------------------------------------
  // 보내기
  // ------------------------------------------------------------------------

  function flipBit(b64, pickIndex) {
    const bytes = C.b64decode(b64);
    bytes[pickIndex(bytes.length)] ^= 0x01;
    return C.b64encode(bytes);
  }

  /** 검증 도구: 암호화가 끝난 봉투를 보내기 직전에 한 군데 바꾼다. */
  function tamperPayload(payload, mode) {
    const out = { ...payload };
    if (mode === 'ciphertext') out.ciphertext = flipBit(payload.ciphertext, () => 0);
    if (mode === 'tag') out.ciphertext = flipBit(payload.ciphertext, (n) => n - 1); // 태그는 마지막 16바이트
    if (mode === 'iv') out.iv = flipBit(payload.iv, () => 0);
    if (mode === 'seq') out.seq = payload.seq + 1;
    return out;
  }

  function sendCurrent() {
    const peer = activePeer();
    if (!peer || !peer.online || !state.connected) return;
    const text = el.messageInput.value;
    if (!text.trim()) return;
    if (text.length > C.MAX_TEXT_LENGTH) {
      showBanner(`메시지는 ${C.MAX_TEXT_LENGTH}자까지 보낼 수 있습니다.`, 'warn');
      return;
    }
    el.messageInput.value = '';

    const tamper = el.tamperMode.value === 'none' ? null : el.tamperMode.value;
    el.tamperMode.value = 'none';

    const entry = { kind: 'out', text, time: Date.now(), status: 'sending', tamper };
    addEntry(peer, entry);
    const relay = state.relay;
    const epoch = peer.epoch;
    peer.outbox = peer.outbox.then(() => deliver(relay, peer, epoch, entry));
  }

  async function deliver(relay, peer, epoch, entry) {
    try {
      if (peer.epoch !== epoch || !peer.online) throw new Error('상대가 나가서 보내지 못했습니다');
      const session = await getSession(peer);
      if (peer.epoch !== epoch) throw new Error('상대 키가 바뀌어 보내지 못했습니다');

      const seq = peer.sendSeq++;
      const payload = await C.encryptMessage(session, seq, entry.text, entry.time);
      const wirePayload = entry.tamper ? tamperPayload(payload, entry.tamper) : payload;
      if (!entry.tamper) peer.lastSent = wirePayload;
      entry.wire = { type: 'relay', to: peer.id, payload: wirePayload };
      updateEntry(entry);

      const ack = await relay.relay(peer.id, wirePayload);
      entry.status = ack.delivered ? 'delivered' : 'undelivered';
    } catch (err) {
      entry.status = 'failed';
      entry.note = err.message;
    }
    updateEntry(entry);
    updateComposer();
  }

  /** 검증 도구: 이미 보낸 정상 봉투를 한 번 더 보낸다. 수신 측은 seq로 걸러야 한다. */
  function replayLast() {
    const peer = activePeer();
    if (!peer || !peer.online || !peer.lastSent || !state.connected) return;
    const payload = peer.lastSent;
    const entry = {
      kind: 'system',
      level: 'warn',
      text: `마지막 메시지(seq ${payload.seq})를 그대로 다시 보냈습니다. 재전송 공격 시연입니다.`,
      wire: { type: 'relay', to: peer.id, payload },
    };
    addEntry(peer, entry);
    const relay = state.relay;
    peer.outbox = peer.outbox.then(() => relay.relay(peer.id, payload).catch((err) => {
      entry.text += ` (전송 실패: ${err.message})`;
      updateEntry(entry);
    }));
  }

  // ------------------------------------------------------------------------
  // 받기
  // ------------------------------------------------------------------------

  function onMessage(frame) {
    const peer = state.peers.get(frame.from);
    if (!peer) return; // 서버가 접속을 알리지 않은 발신자
    peer.inbox = peer.inbox.then(() => receive(peer, frame));
  }

  async function receive(peer, frame) {
    let session;
    try {
      session = await getSession(peer);
    } catch (err) {
      addEntry(peer, {
        kind: 'system',
        level: 'error',
        text: `${peer.id}님의 공개키에 문제가 있어 메시지를 복호화할 수 없습니다. ${err.message}`,
        wire: frame,
      });
      return;
    }

    let msg;
    try {
      msg = await C.decryptMessage(session, frame.payload);
    } catch (err) {
      // 인증 전에는 아무것도 표시하지 않는다
      addEntry(peer, {
        kind: 'system',
        level: 'error',
        text: `${peer.id}님이 보낸 메시지 1건을 폐기했습니다. ${err.message}`,
        wire: frame,
      });
      return;
    }

    // 인증에 성공한 seq만 기준값을 올린다. 그래야 seq를 위조해도 기준값을 밀어낼 수 없다.
    if (frame.payload.seq <= peer.lastRecvSeq) {
      addEntry(peer, {
        kind: 'system',
        level: 'warn',
        text: `재전송된 메시지를 감지해 폐기했습니다 (seq ${frame.payload.seq}, 마지막으로 받은 seq ${peer.lastRecvSeq}).`,
        wire: frame,
      });
      return;
    }
    peer.lastRecvSeq = frame.payload.seq;
    addEntry(peer, { kind: 'in', text: msg.text, time: msg.sent_at, wire: frame });
  }

  // ------------------------------------------------------------------------
  // 접속자 변화
  // ------------------------------------------------------------------------

  function onPeerOnline({ id, pubkey }) {
    // ID는 HKDF info와 AAD에 '|' 구분자로 들어가므로 서버 규칙에 맞는 ID만 받는다
    if (id === state.me.id || !NICK_RE.test(id)) return;
    let peer = state.peers.get(id);
    if (!peer) {
      peer = newPeer(id, pubkey);
      state.peers.set(id, peer);
    } else {
      const keyChanged = peer.pubB64 !== pubkey;
      resetSession(peer);
      peer.pubB64 = pubkey;
      peer.online = true;
      addEntry(peer, {
        kind: 'system',
        level: keyChanged ? 'warn' : 'info',
        text: keyChanged
          ? `${id}님이 다시 접속했습니다. 새 키로 대화하므로 안전 번호를 다시 확인하세요.`
          : `${id}님이 다시 접속했습니다.`,
      });
    }
    renderPeers();
    if (peer.id === state.activeId) {
      refreshHeader(peer);
      getSession(peer).catch(() => {});
    }
  }

  function onPeerOffline({ id }) {
    const peer = state.peers.get(id);
    if (!peer) return;
    peer.online = false;
    resetSession(peer);

    // 주고받은 메시지가 없고 보고 있는 대화도 아니면 목록에서 뺀다
    if (id !== state.activeId && !peer.entries.some((e) => e.kind !== 'system')) {
      state.peers.delete(id);
    } else {
      addEntry(peer, { kind: 'system', level: 'info', text: `${id}님이 나갔습니다. 이 대화의 세션 키를 폐기했습니다.` });
    }
    renderPeers();
    refreshHeader(peer);
  }

  function onClosed({ reason }) {
    state.connected = false;
    for (const peer of state.peers.values()) {
      peer.online = false;
      resetSession(peer);
    }
    state.me.keyPair = null;
    setConnStatus(false, '연결 끊김');
    showBanner(`서버와 연결이 끊어졌습니다: ${reason}. 다시 접속하면 새 키 쌍으로 시작합니다.`, 'error', true);
    renderPeers();
    refreshHeader(activePeer());
  }

  // ------------------------------------------------------------------------
  // 접속 / 나가기
  // ------------------------------------------------------------------------

  function defaultServerUrl() {
    if (location.protocol === 'http:' || location.protocol === 'https:') {
      return `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`;
    }
    return 'ws://localhost:8000/ws';
  }

  async function login(ev) {
    ev.preventDefault();
    const nickname = el.nickname.value.trim();
    const url = el.serverUrl.value.trim();
    if (!NICK_RE.test(nickname)) {
      el.loginError.textContent = '닉네임은 2~20자의 한글, 영문, 숫자, _, - 만 쓸 수 있습니다.';
      return;
    }
    if (!/^wss?:\/\/\S+$/.test(url)) {
      el.loginError.textContent = '서버 주소는 ws:// 또는 wss:// 로 시작해야 합니다.';
      return;
    }

    el.loginError.textContent = '';
    el.loginButton.disabled = true;
    el.loginButton.textContent = '접속 중…';
    const s = newState();
    try {
      const keyPair = await C.generateKeyPair();
      const publicRaw = await C.exportPublicKey(keyPair.publicKey);
      s.me = { id: nickname, keyPair, publicRaw, publicB64: C.b64encode(publicRaw) };
      s.relay = new RelayClient();
      s.relay
        .on('peer_online', (d) => state === s && onPeerOnline(d))
        .on('peer_offline', (d) => state === s && onPeerOffline(d))
        .on('message', (d) => state === s && onMessage(d))
        .on('close', (d) => state === s && onClosed(d))
        .on('server_error', (d) => state === s && showBanner(`서버 오류: ${d.reason}`, 'error'));

      const { users } = await s.relay.connect(url, nickname, s.me.publicB64);
      state = s;
      state.connected = true;
      for (const u of users) {
        if (u.id !== nickname && NICK_RE.test(u.id)) state.peers.set(u.id, newPeer(u.id, u.pubkey));
      }
      enterChat();
    } catch (err) {
      if (s.relay) s.relay.close();
      el.loginError.textContent = err.message;
    } finally {
      el.loginButton.disabled = false;
      el.loginButton.textContent = '접속';
    }
  }

  function logout() {
    if (!state) return;
    const s = state;
    state = null; // 이후 도착하는 이벤트는 무시된다
    s.relay.close('나가기');
    showLogin(s.me.id);
  }

  function showLogin(nickname) {
    el.chatView.hidden = true;
    el.loginView.hidden = false;
    if (nickname) el.nickname.value = nickname;
    el.nickname.focus();
  }

  function enterChat() {
    el.loginView.hidden = true;
    el.chatView.hidden = false;
    el.meName.textContent = state.me.id;
    el.myPubkey.value = state.me.publicB64;
    el.tamperMode.value = 'none';
    hideBanner();
    setConnStatus(true, '연결됨');
    renderPeers();
    renderConversation();
  }

  // ------------------------------------------------------------------------
  // 화면 그리기
  // ------------------------------------------------------------------------

  function textEl(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    node.textContent = text;
    return node;
  }

  function formatTime(ms) {
    return new Date(ms).toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit' });
  }

  function setConnStatus(ok, text) {
    el.connDot.className = `dot ${ok ? 'on' : 'off'}`;
    el.connText.textContent = text;
  }

  function showBanner(text, level, withReconnect) {
    el.banner.replaceChildren(textEl('span', '', text));
    if (withReconnect) {
      const btn = textEl('button', 'secondary', '다시 접속');
      btn.type = 'button';
      btn.addEventListener('click', () => {
        const nickname = state ? state.me.id : '';
        state = null;
        showLogin(nickname);
      });
      el.banner.append(btn);
    }
    el.banner.className = `banner ${level}`;
    el.banner.hidden = false;
  }

  function hideBanner() {
    el.banner.hidden = true;
    el.banner.replaceChildren();
  }

  function renderPeers() {
    const peers = [...state.peers.values()].sort(
      (a, b) => (Number(b.online) - Number(a.online)) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
    );
    el.peerList.replaceChildren(...peers.map((peer) => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'peer' + (peer.id === state.activeId ? ' active' : '') + (peer.online ? '' : ' offline');
      btn.dataset.peer = peer.id;
      btn.append(textEl('span', `dot ${peer.online ? 'on' : 'off'}`, ''));
      btn.append(textEl('span', 'peer-name', peer.id));
      if (peer.unread > 0) btn.append(textEl('span', 'unread', String(peer.unread)));
      btn.addEventListener('click', () => selectPeer(peer.id));
      const li = document.createElement('li');
      li.append(btn);
      return li;
    }));
    el.peerEmpty.hidden = state.peers.size > 0;
  }

  function selectPeer(id) {
    const peer = state.peers.get(id);
    if (!peer) return;
    state.activeId = id;
    peer.unread = 0;
    renderPeers();
    renderConversation();
    if (peer.online && state.connected) getSession(peer).catch(() => {});
    el.messageInput.focus();
  }

  function renderConversation() {
    const peer = activePeer();
    el.placeholder.hidden = !!peer;
    el.convHeader.hidden = !peer;
    el.messages.hidden = !peer;
    el.sendForm.hidden = !peer;
    if (!peer) return;
    el.messages.replaceChildren(...peer.entries.map(renderEntry));
    refreshHeader(peer);
    scrollToBottom();
  }

  function refreshHeader(peer) {
    if (!peer || !state || peer.id !== state.activeId) return;
    el.convName.textContent = peer.id;

    let label;
    let cls;
    if (!peer.online) {
      label = '오프라인';
      cls = 'off';
    } else if (peer.keyError) {
      label = '키 오류';
      cls = 'bad';
    } else if (peer.session) {
      label = peer.verified ? '종단간 암호화 · 안전 번호 확인됨' : '종단간 암호화';
      cls = 'ok';
    } else {
      label = '키 계산 중';
      cls = 'pending';
    }
    el.convState.textContent = label;
    el.convState.className = `badge ${cls}`;

    const showSafety = !!(peer.session && peer.online);
    el.safety.hidden = !showSafety;
    if (showSafety) {
      el.safetyNumber.textContent = peer.session.safetyNumber;
      el.safetyVerified.checked = peer.verified;
    }
    updateComposer();
  }

  function updateComposer() {
    const peer = activePeer();
    const canSend = !!(peer && peer.online && !peer.keyError && state.connected);
    el.messageInput.disabled = !canSend;
    el.sendButton.disabled = !canSend;
    el.replayButton.disabled = !(canSend && peer.lastSent);
    el.messageInput.placeholder = canSend
      ? '메시지 입력 (Enter 전송, Shift+Enter 줄바꿈)'
      : '지금은 메시지를 보낼 수 없습니다';
  }

  function metaText(entry) {
    const parts = [formatTime(entry.time)];
    if (entry.kind === 'out') {
      parts.push(STATUS_LABELS[entry.status]);
      if (entry.tamper) parts.push(`검증 도구: ${TAMPER_LABELS[entry.tamper]}`);
      if (entry.note) parts.push(entry.note);
    } else {
      parts.push('인증 확인됨');
    }
    return parts.join(' · ');
  }

  function renderEntry(entry) {
    const li = document.createElement('li');
    li.className = `entry ${entry.kind}${entry.level ? ` ${entry.level}` : ''}${entry.tamper ? ' tampered' : ''}`;
    if (entry.kind === 'system') {
      li.append(textEl('div', 'system-text', entry.text));
    } else {
      const bubble = document.createElement('div');
      bubble.className = 'bubble';
      bubble.append(textEl('div', 'text', entry.text));
      bubble.append(textEl('div', 'meta', metaText(entry)));
      li.append(bubble);
    }
    if (entry.wire) {
      const details = document.createElement('details');
      details.className = 'wire';
      details.append(textEl('summary', '', entry.kind === 'out' || entry.wire.type === 'relay'
        ? '서버로 보낸 데이터'
        : '서버에서 받은 데이터'));
      details.append(textEl('pre', '', JSON.stringify(entry.wire, null, 2)));
      li.append(details);
    }
    entry.node = li;
    return li;
  }

  function addEntry(peer, entry) {
    if (entry.time === undefined) entry.time = Date.now();
    peer.entries.push(entry);
    if (state && peer.id === state.activeId) {
      el.messages.append(renderEntry(entry));
      scrollToBottom();
    } else if (state && (entry.kind === 'in' || entry.level === 'error')) {
      peer.unread += 1;
      renderPeers();
    }
  }

  function updateEntry(entry) {
    const old = entry.node;
    if (old && old.parentNode) old.replaceWith(renderEntry(entry));
  }

  function scrollToBottom() {
    el.messages.scrollTop = el.messages.scrollHeight;
  }

  // ------------------------------------------------------------------------
  // 시작
  // ------------------------------------------------------------------------

  function init() {
    el.serverUrl.value = defaultServerUrl();

    if (!C.isAvailable()) {
      el.loginError.textContent =
        '이 주소에서는 브라우저 암호화 기능(Web Crypto)을 쓸 수 없습니다. '
        + 'client/index.html 파일을 직접 열거나 localhost 또는 HTTPS 주소로 열어 주세요.';
      el.loginButton.disabled = true;
      return;
    }

    el.loginForm.addEventListener('submit', login);
    el.logoutButton.addEventListener('click', logout);
    el.replayButton.addEventListener('click', replayLast);
    el.sendForm.addEventListener('submit', (ev) => {
      ev.preventDefault();
      sendCurrent();
    });
    el.messageInput.addEventListener('keydown', (ev) => {
      // 한글 조합 중 Enter는 글자 확정용이므로 전송하지 않는다
      if (ev.key === 'Enter' && !ev.shiftKey && !ev.isComposing && ev.keyCode !== 229) {
        ev.preventDefault();
        sendCurrent();
      }
    });
    el.safetyVerified.addEventListener('change', () => {
      const peer = activePeer();
      if (!peer || !peer.session) return;
      peer.verified = el.safetyVerified.checked;
      refreshHeader(peer);
    });
    el.nickname.focus();
  }

  init();
})();
