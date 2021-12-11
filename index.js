const createModule = require('./ecdsa_c')
const setupFactory = require('./ecdsa')

const getRandomValues = (buf) => {
  if (typeof window === 'object') {
    // for Browser
    const crypto = window.crypto || window.msCrypto
    return crypto.getRandomValues(buf)
  } else if (typeof self === 'object' && typeof self.crypto === 'object' && typeof self.crypto.getRandomValues === 'function') {
    // for Worker
    const crypto = self.crypto
    return crypto.getRandomValues(buf)
  } else {
    // for Node.js
    const crypto = require('crypto')
    return crypto.randomFillSync(buf)
  }
}

const ecdsa = setupFactory(createModule, getRandomValues)

module.exports = ecdsa
