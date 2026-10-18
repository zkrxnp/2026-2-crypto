// 암호 모듈 단위 테스트: node --test tests/client/
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('../../client/crypto.js');

async function makeUser(id) {
  const keyPair = await C.generateKeyPair();
  const publicRaw = await C.exportPublicKey(keyPair.publicKey);
  return { id, keyPair, publicRaw };
}

function session(me, peer) {
  return C.deriveSession({
    myId: me.id,
    myPrivateKey: me.keyPair.privateKey,
    myPublicRaw: me.publicRaw,
    peerId: peer.id,
    peerPublicRaw: peer.publicRaw,
  });
}

async function pair() {
  const alice = await makeUser('alice');
  const bob = await makeUser('bob');
  return { alice, bob, a: await session(alice, bob), b: await session(bob, alice) };
}

async function rejectsWith(promise, code) {
  await assert.rejects(promise, (err) => err instanceof C.CryptoError && err.code === code);
}

test('개인키는 내보낼 수 없다', async () => {
  const { keyPair } = await makeUser('alice');
  assert.equal(keyPair.privateKey.extractable, false);
  await assert.rejects(crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
});

test('공개키는 65바이트 비압축 점이고 base64로 88자다', async () => {
  const { publicRaw } = await makeUser('alice');
  assert.equal(publicRaw.length, 65);
  assert.equal(publicRaw[0], 0x04);
  assert.equal(C.b64encode(publicRaw).length, 88);
});

test('양쪽이 같은 키를 파생해 서로의 메시지를 복호화한다', async () => {
  const { a, b } = await pair();
  const m1 = await C.encryptMessage(a, 0, '안녕 bob', 1000);
  assert.deepEqual(await C.decryptMessage(b, m1), { text: '안녕 bob', sent_at: 1000 });
  const m2 = await C.encryptMessage(b, 0, '안녕 alice', 2000);
  assert.deepEqual(await C.decryptMessage(a, m2), { text: '안녕 alice', sent_at: 2000 });
});

test('양쪽 안전 번호가 같고 5자리 6묶음이다', async () => {
  const { a, b } = await pair();
  assert.equal(a.safetyNumber, b.safetyNumber);
  assert.match(a.safetyNumber, /^\d{5}( \d{5}){5}$/);
});

test('방향별 키가 분리되어 있다: 내가 보낸 메시지를 내 수신키로 풀 수 없다', async () => {
  const { a } = await pair();
  const mine = await C.encryptMessage(a, 0, 'hello', 1);
  const reflected = { ...mine };
  // 같은 메시지를 상대가 보낸 것처럼 되돌려 받아도 (AAD와 키가 모두 달라) 실패해야 한다
  await rejectsWith(C.decryptMessage(a, reflected), 'AUTH_FAILED');
});

test('송신키는 encrypt 전용, 수신키는 decrypt 전용이다', async () => {
  const { a } = await pair();
  assert.deepEqual(a.sendKey.usages, ['encrypt']);
  assert.deepEqual(a.recvKey.usages, ['decrypt']);
  assert.equal(a.sendKey.extractable, false);
  assert.equal(a.recvKey.extractable, false);
});

test('제3자는 복호화할 수 없다', async () => {
  const { alice, bob, a } = await pair();
  const eve = await makeUser('eve');
  // eve가 bob을 사칭해 alice 공개키로 세션을 만들어도 bob의 개인키가 없으면 키가 다르다
  const eveAsBob = await C.deriveSession({
    myId: 'bob', myPrivateKey: eve.keyPair.privateKey, myPublicRaw: bob.publicRaw,
    peerId: 'alice', peerPublicRaw: alice.publicRaw,
  });
  const msg = await C.encryptMessage(a, 0, 'secret', 1);
  await rejectsWith(C.decryptMessage(eveAsBob, msg), 'AUTH_FAILED');
});

test('공개키가 바뀌면 (재접속) 이전 세션으로는 복호화할 수 없다', async () => {
  const { alice, b } = await pair();
  const bob2 = await makeUser('bob');
  const a2 = await session(alice, bob2);
  const msg = await C.encryptMessage(a2, 0, 'new session', 1);
  await rejectsWith(C.decryptMessage(b, msg), 'AUTH_FAILED');
  assert.notEqual(a2.safetyNumber, b.safetyNumber);
});

for (const [name, mutate] of [
  ['암호문 1비트', (p) => ({ ...p, ciphertext: flip(p.ciphertext, 0) })],
  ['인증 태그 1비트', (p) => ({ ...p, ciphertext: flip(p.ciphertext, -1) })],
  ['IV 1비트', (p) => ({ ...p, iv: flip(p.iv, 0) })],
  ['seq(AAD)', (p) => ({ ...p, seq: p.seq + 1 })],
]) {
  test(`변조 검출: ${name}`, async () => {
    const { a, b } = await pair();
    const msg = await C.encryptMessage(a, 5, '변조 테스트', 1);
    await rejectsWith(C.decryptMessage(b, mutate(msg)), 'AUTH_FAILED');
    // 원본은 그대로 복호화된다
    assert.equal((await C.decryptMessage(b, msg)).text, '변조 테스트');
  });
}

function flip(b64, index) {
  const bytes = C.b64decode(b64);
  bytes[index < 0 ? bytes.length + index : index] ^= 0x01;
  return C.b64encode(bytes);
}

test('IV는 메시지마다 다르다', async () => {
  const { a } = await pair();
  const ivs = new Set();
  for (let i = 0; i < 200; i++) ivs.add((await C.encryptMessage(a, i, 'x', 1)).iv);
  assert.equal(ivs.size, 200);
});

test('봉투 형식 오류는 BAD_PAYLOAD로 거부한다', async () => {
  const { a, b } = await pair();
  const msg = await C.encryptMessage(a, 0, 'x', 1);
  await rejectsWith(C.decryptMessage(b, { ...msg, seq: -1 }), 'BAD_PAYLOAD');
  await rejectsWith(C.decryptMessage(b, { ...msg, seq: '0' }), 'BAD_PAYLOAD');
  await rejectsWith(C.decryptMessage(b, { ...msg, iv: C.b64encode(new Uint8Array(16)) }), 'BAD_PAYLOAD');
  await rejectsWith(C.decryptMessage(b, { ...msg, ciphertext: C.b64encode(new Uint8Array(16)) }), 'BAD_PAYLOAD');
  await rejectsWith(C.decryptMessage(b, { ...msg, iv: '***' }), 'BAD_PAYLOAD');
});

test('잘못된 공개키는 BAD_KEY로 거부한다', async () => {
  const alice = await makeUser('alice');
  const notOnCurve = new Uint8Array(65);
  notOnCurve[0] = 0x04;
  notOnCurve[1] = 1;
  for (const bad of [new Uint8Array(64), notOnCurve, alice.publicRaw]) {
    await rejectsWith(C.deriveSession({
      myId: 'alice', myPrivateKey: alice.keyPair.privateKey, myPublicRaw: alice.publicRaw,
      peerId: 'bob', peerPublicRaw: bad,
    }), 'BAD_KEY');
  }
});

test('메시지 길이 제한', async () => {
  const { a } = await pair();
  await rejectsWith(C.encryptMessage(a, 0, '', 1), 'BAD_PLAINTEXT');
  await rejectsWith(C.encryptMessage(a, 0, 'x'.repeat(C.MAX_TEXT_LENGTH + 1), 1), 'BAD_PLAINTEXT');
  await C.encryptMessage(a, 0, '가'.repeat(C.MAX_TEXT_LENGTH), 1);
});

test('base64url 입력도 받는다', () => {
  const bytes = new Uint8Array([251, 255, 254, 0, 1]);
  const std = C.b64encode(bytes);
  const url = std.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  assert.deepEqual(C.b64decode(url), bytes);
});
