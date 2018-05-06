[![Build Status](https://travis-ci.org/herumi/ecdsa-wasm.png)](https://travis-ci.org/herumi/ecdsa-wasm)
# ECSSA/secp256k1 + SHA-256

# Abstract

This is a wasm version of [mcl/ecdsa.h](https://github.com/herumi/mcl/blob/master/include/mcl/ecdsa.h)

## for Node.js
node test.js

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
