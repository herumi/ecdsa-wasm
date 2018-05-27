(generator => {
  if (typeof exports === 'object') {
    const crypto = require('crypto')
    crypto.getRandomValues = crypto.randomFillSync
    generator(exports, crypto, true)
  } else {
    const crypto = window.crypto || window.msCrypto
    const exports = {}
    window.ecdsa = generator(exports, crypto, false)
  }
})((exports, crypto, isNodeJs) => {
  const setup = (exports) => {
    const mod = exports.mod
    const ECDSA_FP_SIZE = 32
    const ECDSA_SECRETKEY_SIZE = ECDSA_FP_SIZE
    const ECDSA_PUBLICKEY_SIZE = ECDSA_FP_SIZE * 3
    const ECDSA_SIGNATURE_SIZE = ECDSA_FP_SIZE * 2

    const _malloc = pos => {
      return mod._ecdsaMalloc(pos)
    }
    const _free = pos => {
      mod._ecdsaFree(pos)
    }
    const ptrToAsciiStr = (pos, n) => {
      let s = ''
      for (let i = 0; i < n; i++) {
        s += String.fromCharCode(mod.HEAP8[pos + i])
      }
      return s
    }
    const asciiStrToPtr = (pos, s) => {
      for (let i = 0; i < s.length; i++) {
        mod.HEAP8[pos + i] = s.charCodeAt(i)
      }
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
    const _wrapGetStr = (func, returnAsStr = true) => {
      return (x, ioMode = 0) => {
        const maxBufSize = 3096
        const pos = _malloc(maxBufSize)
        const n = func(pos, maxBufSize, x, ioMode)
        if (n <= 0) {
          throw new Error('err gen_str:' + x)
        }
        let s = null
        if (returnAsStr) {
          s = ptrToAsciiStr(pos, n)
        } else {
          s = new Uint8Array(mod.HEAP8.subarray(pos, pos + n))
        }
        _free(pos)
        return s
      }
    }
    const _wrapSerialize = func => {
      return _wrapGetStr(func, false)
    }
    const _wrapDeserialize = func => {
      return (x, buf) => {
        const pos = _malloc(buf.length)
        mod.HEAP8.set(buf, pos)
        const r = func(x, pos, buf.length)
        _free(pos)
        if (r === 0) throw new Error('err _wrapDeserialize', buf)
      }
    }
    /*
      argNum : n
      func(x0, ..., x_(n-1), buf, ioMode)
      => func(x0, ..., x_(n-1), pos, buf.length, ioMode)
    */
    const _wrapInput = (func, argNum, returnValue = false) => {
      return function () {
        const args = [...arguments]
        const buf = args[argNum]
        const typeStr = Object.prototype.toString.apply(buf)
        if (['[object String]', '[object Uint8Array]', '[object Array]'].indexOf(typeStr) < 0) {
          throw new Error(`err bad type:"${typeStr}". Use String or Uint8Array.`)
        }
        const ioMode = args[argNum + 1] // may undefined
        const pos = _malloc(buf.length)
        if (typeStr === '[object String]') {
          asciiStrToPtr(pos, buf)
        } else {
          mod.HEAP8.set(buf, pos)
        }
        const r = func(...args.slice(0, argNum), pos, buf.length, ioMode)
        _free(pos)
        if (returnValue) return r
        if (r) throw new Error('err _wrapInput ' + buf)
      }
    }
    exports.ecdsaInit = () => {
      const r = mod._ecdsaInit()
      if (r) throw new Error('ecdsaInit err ' + r)
    }

    mod.ecdsaSecretKeySerialize = _wrapSerialize(mod._ecdsaSecretKeySerialize)
    mod.ecdsaPublicKeySerialize = _wrapSerialize(mod._ecdsaPublicKeySerialize)
    mod.ecdsaSignatureSerialize = _wrapSerialize(mod._ecdsaSignatureSerialize)

    mod.ecdsaSecretKeyDeserialize = _wrapDeserialize(mod._ecdsaSecretKeyDeserialize)
    mod.ecdsaPublicKeyDeserialize = _wrapDeserialize(mod._ecdsaPublicKeyDeserialize)
    mod.ecdsaSignatureDeserialize = _wrapDeserialize(mod._ecdsaSignatureDeserialize)

    mod.ecdsaSign = _wrapInput(mod._ecdsaSign, 2)
    mod.ecdsaVerify = _wrapInput(mod._ecdsaVerify, 2, true)
    mod.ecdsaVerifyPrecomputed = _wrapInput(mod._ecdsaVerifyPrecomputed, 2, true)

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
      // alloc new array
      _alloc () {
        return _malloc(this.a_.length * 4)
      }
      // alloc and copy a_ to mod.HEAP32[pos / 4]
      _allocAndCopy () {
        const pos = this._alloc()
        mod.HEAP32.set(this.a_, pos / 4)
        return pos
      }
      // save pos to a_
      _save (pos) {
        this.a_.set(mod.HEAP32.subarray(pos / 4, pos / 4 + this.a_.length))
      }
      // save and free
      _saveAndFree (pos) {
        this._save(pos)
        _free(pos)
      }
      // set parameter (p1, p2 may be undefined)
      _setter (func, p1, p2) {
        const pos = this._alloc()
        const r = func(pos, p1, p2)
        this._saveAndFree(pos)
        if (r) throw new Error('_setter err')
      }
      // getter (p1, p2 may be undefined)
      _getter (func, p1, p2) {
        const pos = this._allocAndCopy()
        const s = func(pos, p1, p2)
        _free(pos)
        return s
      }
    }

    exports.SecretKey = class extends Common {
      constructor () {
        super(ECDSA_SECRETKEY_SIZE)
      }
      deserialize (s) {
        this._setter(mod.ecdsaSecretKeyDeserialize, s)
      }
      serialize () {
        return this._getter(mod.ecdsaSecretKeySerialize)
      }
      setByCSPRNG () {
        this._setter(mod._ecdsaSecretKeySetByCSPRNG)
      }
      getPublicKey () {
        const pub = new exports.PublicKey()
        const secPos = this._allocAndCopy()
        const pubPos = pub._alloc()
        mod._ecdsaGetPublicKey(pubPos, secPos)
        pub._saveAndFree(pubPos)
        _free(secPos)
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
        const secPos = this._allocAndCopy()
        const sigPos = sig._alloc()
        mod.ecdsaSign(sigPos, secPos, m)
        sig._saveAndFree(sigPos)
        _free(secPos)
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
        this._setter(mod.ecdsaPublicKeyDeserialize, s)
      }
      serialize () {
        return this._getter(mod.ecdsaPublicKeySerialize)
      }
      verify (sig, m) {
        const pubPos = this._allocAndCopy()
        const sigPos = sig._allocAndCopy()
        const r = mod.ecdsaVerify(sigPos, pubPos, m)
        _free(sigPos)
        _free(pubPos)
        return r !== 0
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
        const pubPos = pub._allocAndCopy()
        mod._ecdsaPrecomputedPublicKeyInit(this.p, pubPos)
        _free(pubPos)
      }
      verify (sig, m) {
        const sigPos = sig._allocAndCopy()
        const r = mod.ecdsaVerifyPrecomputed(sigPos, this.p, m)
        _free(sigPos)
        return r !== 0
      }
    }

    exports.Signature = class extends Common {
      constructor () {
        super(ECDSA_SIGNATURE_SIZE)
      }
      deserialize (s) {
        this._setter(mod.ecdsaSignatureDeserialize, s)
      }
      serialize () {
        return this._getter(mod.ecdsaSignatureSerialize)
      }
    }
    exports.deserializeHexStrToSignature = s => {
      const r = new exports.Signature()
      r.deserializeHexStr(s)
      return r
    }
    exports.ecdsaInit()
    console.log('finished')
  } // setup()
  const _cryptoGetRandomValues = function(p, n) {
    const a = new Uint8Array(n)
    crypto.getRandomValues(a)
    for (let i = 0; i < n; i++) {
      exports.mod.HEAP8[p + i] = a[i]
    }
  }
  exports.init = () => {
    const name = 'ecdsa_c'
    return new Promise(resolve => {
      if (isNodeJs) {
        const path = require('path')
        const js = require(`./${name}.js`)
        const Module = {
          cryptoGetRandomValues : _cryptoGetRandomValues,
          locateFile: baseName => { return path.join(__dirname, baseName) }
        }
        js(Module)
          .then(_mod => {
            exports.mod = _mod
            setup(exports)
            resolve()
          })
      } else {
        fetch(`./${name}.wasm`) // eslint-disable-line
          .then(response => response.arrayBuffer())
          .then(buffer => new Uint8Array(buffer))
          .then(() => {
            exports.mod = Module() // eslint-disable-line
            exports.mod.cryptoGetRandomValues = _cryptoGetRandomValues
            exports.mod.onRuntimeInitialized = () => {
              setup(exports)
              resolve()
            }
          })
      }
    })
  }
  return exports
})
