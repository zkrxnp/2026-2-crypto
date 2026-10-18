// test_crosscheck.py가 호출하는 도우미: stdin JSON -> client/crypto.js 실행 -> stdout JSON
'use strict';

const C = require('../../client/crypto.js');

async function main() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  const req = JSON.parse(input);

  const myPrivateKey = await crypto.subtle.importKey(
    'pkcs8', C.b64decode(req.myPkcs8), { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'],
  );
  const session = await C.deriveSession({
    myId: req.myId,
    myPrivateKey,
    myPublicRaw: C.b64decode(req.myPub),
    peerId: req.peerId,
    peerPublicRaw: C.b64decode(req.peerPub),
  });

  const out = { safetyNumber: session.safetyNumber };
  if (req.encrypt) {
    out.payload = await C.encryptMessage(session, req.encrypt.seq, req.encrypt.text, req.encrypt.sentAt);
  }
  if (req.decrypt) {
    try {
      out.plaintext = await C.decryptMessage(session, req.decrypt);
    } catch (err) {
      out.error = err.code;
    }
  }
  process.stdout.write(JSON.stringify(out));
}

main().catch((err) => {
  process.stderr.write(String(err && err.stack || err));
  process.exit(1);
});
