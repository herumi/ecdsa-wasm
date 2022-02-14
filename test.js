'use strict'
const ecdsa = require('./index.js')
const assert = require('assert')
const { performance } = require('perf_hooks')

ecdsa.init()
  .then(() => {
    try {
      serializeDerTest()
      serializeTest()
      signatureTest()
      valueTest()
      console.log('all ok')
      benchAll()
    } catch (e) {
      console.log(`TEST FAIL ${e}`)
      assert(false)
    }
  })

function serializeSubTest (t, Cstr) {
  const s = t.serializeToHexStr()
  const t2 = new Cstr()
  t2.deserializeHexStr(s)
  assert.deepEqual(t.serialize(), t2.serialize())
}

function serializeTest () {
  const sec = new ecdsa.SecretKey()
  sec.setByCSPRNG()
  serializeSubTest(sec, ecdsa.SecretKey)
  const pub = sec.getPublicKey()
  serializeSubTest(pub, ecdsa.PublicKey)
  const msg = 'abc'
  const sig = sec.sign(msg)
  serializeSubTest(sig, ecdsa.Signature)
}

function valueSubTest (msg, secHex, pubHex, sigHex) {
  const sec = ecdsa.deserializeHexStrToSecretKey(secHex)
  const pub = ecdsa.deserializeHexStrToPublicKey(pubHex)
  const sig = ecdsa.deserializeHexStrToSignature(sigHex)
  assert.equal(sec.serializeToHexStr(), secHex)
  assert.equal(pub.serializeToHexStr(), pubHex)
  assert.equal(sig.serializeToHexStr(), sigHex)
  sig.normalize()
  assert(pub.verify(sig, msg))
  {
    const pub2 = sec.getPublicKey()
    assert.equal(pub2.serializeToHexStr(), pubHex)
    assert(pub2.verify(sig, msg))
  }
}

function valueTest () {
  const tbl = [
    {
      msg: 'hello',
      sec: '83ecb3984a4f9ff03e84d5f9c0d7f888a81833643047acc58eb6431e01d9bac8',
      pub: '653bd02ba1367e5d4cd695b6f857d1cd90d4d8d42bc155d85377b7d2d0ed2e7104e8f5da403ab78decec1f19e2396739ea544e2b14159beb5091b30b418b813a',
      sig: 'a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5de5d79a2ba44e311d04fdca263639283965780bce9169822be9cc81756e95a24'
    },
    {
      msg: 'hello',
      sec: 'b1aa6282b14e5ffbf6d12f783612f804e6a20d1a9734ffbb6c9923c670ee8da2',
      pub: '0a09ff142d94bc3f56c5c81b75ea3b06b082c5263fbb5bd88c619fc6393dda3da53e0e930892cdb7799eea8fd45b9fff377d838f4106454289ae8a080b111f8d',
      sig: '50839a97404c24ec39455b996e4888477fd61bcf0ffb960c7ffa3bef104501919671b8315bb5c1611d422d49cbbe7e80c6b463215bfad1c16ca73172155bf31a'
    }
  ]
  ecdsa.setSerializeMode(ecdsa.SerializeOld)
  tbl.forEach(e => {
    valueSubTest(e.msg, e.sec, e.pub, e.sig)
  })
  ecdsa.setSerializeMode(ecdsa.SerializeBitcoin)
}

function serializeDerTest () {
  const rs = 'ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f7a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed'
  const expected = new Uint8Array([0x30, 0x45, 0x02, 0x21, 0x00, 0xed, 0x81, 0xff, 0x19, 0x2e, 0x75, 0xa3, 0xfd, 0x23, 0x04, 0x00, 0x4d, 0xca, 0xdb, 0x74, 0x6f, 0xa5, 0xe2, 0x4c, 0x50, 0x31, 0xcc, 0xfc, 0xf2, 0x13, 0x20, 0xb0, 0x27, 0x74, 0x57, 0xc9, 0x8f, 0x02, 0x20, 0x7a, 0x98, 0x6d, 0x95, 0x5c, 0x6e, 0x0c, 0xb3, 0x5d, 0x44, 0x6a, 0x89, 0xd3, 0xf5, 0x61, 0x00, 0xf4, 0xd7, 0xf6, 0x78, 0x01, 0xc3, 0x19, 0x67, 0x74, 0x3a, 0x9c, 0x8e, 0x10, 0x61, 0x5b, 0xed])
  ecdsa.setSerializeMode(ecdsa.SerializeOld)
  const sig = ecdsa.deserializeHexStrToSignature(rs)
  ecdsa.setSerializeMode(ecdsa.SerializeBitcoin)
  const b = sig.serialize()
  assert.deepEqual(b, expected)
}

function signatureTest () {
  const sec = new ecdsa.SecretKey()

  sec.setByCSPRNG()
  sec.dump('secretKey ')

  const pub = sec.getPublicKey()
  pub.dump('publicKey ')

  const msg = 'doremifa'
  console.log('msg ' + msg)
  const sig = sec.sign(msg)
  sig.dump('signature ')

  assert(pub.verify(sig, msg))

  const ppub = new ecdsa.PrecomputedPublicKey()
  ppub.init(pub)
  assert(ppub.verify(sig, msg))

  // bad signature
  sig.a_[0]++
  assert(!pub.verify(sig, msg))
  assert(!ppub.verify(sig, msg))

  ppub.destroy() // necessary to avoid memory leak
}

function bench (label, count, func) {
  const start = performance.now()
  for (let i = 0; i < count; i++) {
    func()
  }
  const end = performance.now()
  const t = (end - start) / count
  const roundTime = (Math.round(t * 1000)) / 1000
  console.log(label + ' ' + roundTime)
}

function benchEcdsa () {
  const msg = 'hello wasm'
  const sec = new ecdsa.SecretKey()
  sec.setByCSPRNG()
  const pub = sec.getPublicKey()
  bench('sign', 50, () => sec.sign(msg))
  const sig = sec.sign(msg)
  bench('verify', 50, () => pub.verify(sig, msg))
  const ppub = new ecdsa.PrecomputedPublicKey()
  ppub.init(pub)
  bench('precomputed verify', 50, () => ppub.verify(sig, msg))
  ppub.destroy()
}

function benchAll () {
  benchEcdsa()
}
