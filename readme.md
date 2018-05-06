[![Build Status](https://travis-ci.org/herumi/ecdsa-wasm.png)](https://travis-ci.org/herumi/ecdsa-wasm)
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

```
mkdir work
cd work
git clone git@github.com:herumi/mcl
git clone git@github.com:herumi/cybozulib
mkdir ecdsa-wasm
cd mcl
make ecdsa-wasm
```

# License

modified new BSD License
http://opensource.org/licenses/BSD-3-Clause

# Author

光成滋生 MITSUNARI Shigeo(herumi@nifty.com)
