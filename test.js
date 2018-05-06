'use strict'
const ecdsa = require('./ecdsa.js')
const assert = require('assert')
const { performance } = require('perf_hooks')

ecdsa.init()
  .then(() => {
    try {
      serializeTest()
      signatureTest()
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
