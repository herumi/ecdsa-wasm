const setupFactory = (createModule, getRandomValues) => {
  const exports = {}
  const setup = (exports) => {
    const mod = exports.mod
    const ECDSA_FP_SIZE = 32
    const ECDSA_SECRETKEY_SIZE = ECDSA_FP_SIZE
    const ECDSA_PUBLICKEY_SIZE = ECDSA_FP_SIZE * 3
    const ECDSA_SIGNATURE_SIZE = ECDSA_FP_SIZE * 2

    // shared wrappers defined in mcl/src/wasm/glue.js (embedded in ecdsa_c.js);
    // values are passed as Uint32Array (a_) and the stack is restored in finally
    const stackSave = mod.stackSave
    const stackAlloc = mod.stackAlloc
    const stackRestore = mod.stackRestore
    const sallocCopy = mod.sallocCopy
    const copyFromHeap32 = mod.copyFromHeap32
    const callSetter = mod.callSetter
    const callGetter = mod.callGetter
    const callOp1 = mod.callOp1
    const callOp1Input = mod.callOp1Input
    const callGetter2Input = mod.callGetter2Input
    const callDeserialize = mod.callDeserialize
    const callSerialize = mod.callSerialize
    // stack alloc and copy a message (String or Uint8Array) ; return its position
    // (caller must wrap in stackSave/try/finally/stackRestore)
    const sallocInput = buf => {
      const isStr = typeof buf === 'string'
      if (!isStr && !(buf instanceof Uint8Array) && !Array.isArray(buf)) {
        throw new Error('err bad type:"' + Object.prototype.toString.apply(buf) + '". Use String or Uint8Array.')
      }
      const pos = stackAlloc(buf.length)
      if (isStr) {
        mod.asciiStrToPtr(pos, buf)
      } else {
        mod.HEAP8.set(buf, pos)
      }
      return pos
    }
    exports.toHex = (a, start, n) => {
      let s = ''
      for (let i = 0; i < n; i++) {
        s += ('0' + a[start + i].toString(16)).slice(-2)
      }
      return s
    }
    // Uint8Array to hex string
    exports.toHexStr = a => {
      return exports.toHex(a, 0, a.length)
    }
    // hex string to Uint8Array
    exports.fromHexStr = s => {
      if (s.length & 1) throw new Error('fromHexStr:length must be even ' + s.length)
      const n = s.length / 2
      const a = new Uint8Array(n)
      for (let i = 0; i < n; i++) {
        a[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16)
      }
      return a
    }
    class Common {
      constructor (size) {
        this.a_ = new Uint32Array(size / 4)
      }

      deserializeHexStr (s) {
        this.deserialize(exports.fromHexStr(s))
      }

      serializeToHexStr () {
        return exports.toHexStr(this.serialize())
      }

      dump (msg = '') {
        console.log(msg + this.serializeToHexStr())
      }

      clear () {
        this.a_.fill(0)
      }

      // this = func(p1, p2) ; throw if func returns non-zero (p1, p2 may be undefined)
      _setter (func, p1, p2) {
        callSetter(func, this.a_, p1, p2)
      }

      // return func(this, p1, p2)
      _getter (func, p1, p2) {
        return callGetter(func, this.a_, p1, p2)
      }

      _deserialize (func, buf) {
        callDeserialize(func, this.a_, buf)
      }

      _serialize (func) {
        return callSerialize(func, this.a_)
      }
    }

    exports.SecretKey = class extends Common {
      constructor () {
        super(ECDSA_SECRETKEY_SIZE)
      }

      deserialize (s) {
        this._deserialize(mod._ecdsaSecretKeyDeserialize, s)
      }

      serialize () {
        return this._serialize(mod._ecdsaSecretKeySerialize)
      }

      setByCSPRNG () {
        this._setter(mod._ecdsaSecretKeySetByCSPRNG)
      }

      getPublicKey () {
        const pub = new exports.PublicKey()
        callOp1(mod._ecdsaGetPublicKey, pub.a_, this.a_)
        return pub
      }

      /*
        input
        m : message (string or Uint8Array)
        return
        BlsSignature
      */
      sign (m) {
        const sig = new exports.Signature()
        const r = callOp1Input(mod._ecdsaSign, sig.a_, this.a_, m)
        if (r) throw new Error('err ecdsaSign')
        return sig
      }
    }
    exports.deserializeHexStrToSecretKey = s => {
      const r = new exports.SecretKey()
      r.deserializeHexStr(s)
      return r
    }

    exports.PublicKey = class extends Common {
      constructor () {
        super(ECDSA_PUBLICKEY_SIZE)
      }

      deserialize (s) {
        this._deserialize(mod._ecdsaPublicKeyDeserialize, s)
      }

      serialize () {
        return this._serialize(mod._ecdsaPublicKeySerialize)
      }

      serializeCompressed () {
        return this._serialize(mod._ecdsaPublicKeySerializeCompressed)
      }

      verify (sig, m) {
        return callGetter2Input(mod._ecdsaVerify, sig.a_, this.a_, m) !== 0
      }
    }
    exports.deserializeHexStrToPublicKey = s => {
      const r = new exports.PublicKey()
      r.deserializeHexStr(s)
      return r
    }
    exports.PrecomputedPublicKey = class {
      constructor () {
        this.p = mod._ecdsaPrecomputedPublicKeyCreate()
      }

      /*
        call destroy if PrecomputedPublicKey is not necessary
        to avoid memory leak
      */
      destroy () {
        if (this.p == null) return
        mod._ecdsaPrecomputedPublicKeyDestroy(this.p)
        this.p = null
      }

      /*
        initialize PrecomputedPublicKey by PublicKey pub
      */
      init (pub) {
        callGetter((pubPos, p) => mod._ecdsaPrecomputedPublicKeyInit(p, pubPos), pub.a_, this.p)
      }

      verify (sig, m) {
        const stack = stackSave()
        try {
          const sigPos = sallocCopy(sig.a_)
          const mPos = sallocInput(m)
          return mod._ecdsaVerifyPrecomputed(sigPos, this.p, mPos, m.length) !== 0
        } finally {
          stackRestore(stack)
        }
      }
    }

    exports.Signature = class extends Common {
      constructor () {
        super(ECDSA_SIGNATURE_SIZE)
      }

      deserialize (s) {
        this._deserialize(mod._ecdsaSignatureDeserialize, s)
      }

      serialize () {
        return this._serialize(mod._ecdsaSignatureSerialize)
      }

      // normalize this to lower S
      normalize () {
        const stack = stackSave()
        try {
          const sigPos = sallocCopy(this.a_)
          mod._ecdsaNormalizeSignature(sigPos)
          copyFromHeap32(this.a_, sigPos)
        } finally {
          stackRestore(stack)
        }
      }
    }
    exports.deserializeHexStrToSignature = s => {
      const r = new exports.Signature()
      r.deserializeHexStr(s)
      return r
    }
    exports.SerializeOld = 0
    exports.SerializeBitcoin = 1 // default
    // mode = SerilizeOld or SerializeBitcoin
    exports.setSerializeMode = mode => {
      mod._ecdsaSetSerializeMode(mode)
    }
    const r = mod._ecdsaInit()
    if (r) throw new Error('ecdsaInit err ' + r)
  } // setup()
  // called from glue.js with a Uint8Array to be filled
  const _cryptoGetRandomValues = function (a) {
    exports.getRandomValues(a)
  }
  exports.getRandFunc = () => {
    return exports.getRandomValues
  }
  exports.setRandFunc = (f) => {
    exports.getRandomValues = f
  }
  exports.init = async () => {
    exports.getRandomValues = getRandomValues
    exports.mod = await createModule({
      cryptoGetRandomValues: _cryptoGetRandomValues,
      prefix: 'ecdsa'
    })
    setup(exports)
  }
  return exports
}

module.exports = setupFactory
