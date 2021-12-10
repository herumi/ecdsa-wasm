[![Build Status](https://github.com/herumi/ecdsa-wasm/actions/workflows/main.yml/badge.svg)](https://github.com/herumi/ecdsa-wasm/actions/workflows/main.yml)

# ECSSA/secp256k1 + SHA-256

# Abstract

This is a wasm version of [mcl/ecdsa.h](https://github.com/herumi/mcl/blob/master/include/mcl/ecdsa.h)

## for Node.js
node test.js

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

## how to build
Install emscripten.

```
cd src
make wasm
```

# License

modified new BSD License
http://opensource.org/licenses/BSD-3-Clause

# Author

光成滋生 MITSUNARI Shigeo(herumi@nifty.com)
