[![Build Status](https://github.com/herumi/ecdsa-wasm/actions/workflows/main.yml/badge.svg)](https://github.com/herumi/ecdsa-wasm/actions/workflows/main.yml)

# ECSSA/secp256k1 + SHA-256

# Abstract

This is a wasm version of [mcl/ecdsa.h](https://github.com/herumi/mcl/blob/master/include/mcl/ecdsa.h)

## News
`serialize()` supports the format defined at [BitCoin](https://www.oreilly.com/library/view/programming-bitcoin/9781492031482/ch04.html)

## for Node.js
```
npm test
```

## how to use
```
const ecdsa = require('ecdsa-wasm')

// create secret key
const sec = new ecdsa.SecretKey()

// initialize sec
sec.setByCSPRNG()

// get public key
const pub = sec.getPublicKey()

// make signature
const sig = sec.sign("abc")

// verify signatpure by pub
> pub.verify(sig, "abc")
true
> pub.verify(sig, "abcd")
false

// create precomputed public key(faster than pub)
const ppub = new ecdsa.PrecomputedPublicKey()
// initialize ppub
ppub.init(pub)

// verify signature by ppub
> ppub.verify(sig, "abc")
true
> ppub.verify(sig, "abcd")
false

// destroy ppub if unnecessary
ppub.destroy()
```

### serialization
- `SecretKey.serialize()` return 32-bytes Uint8Array as big-endian
- `PublicKey.serialize()` return 65-bytes Uint8Array as 0x04 + `x` + `y`
- `PublicKey.serializeCompressed()` return 33-bytes Uint8Array as 0x02 (y is even) or 0x03 (y is odd) + `x`
- `Signature.serialize()` return DER-format
- `SecretKey.deserialize(a)`
- `PublicKey.deserialize(a)`
- `Signature.deserialize(a)`
  - take `Uint8Array` of `a` and constract the object

## how to build ecdsa_c.js

Install emscripten.
```
git clone --recurse-submodules git@github.com:herumi/ecdsa-wasm
cd ecdsa-wasm
make -C src wasm
```

# License

modified new BSD License
http://opensource.org/licenses/BSD-3-Clause

# Author

光成滋生 MITSUNARI Shigeo(herumi@nifty.com)
