const hypercore = require('hypercore')
const crypto = require('hypercore-crypto')
const sodium = require('sodium-universal')
const debug = require('debug')('ciphercore')
const codecs = require('codecs')
const assert = require('assert')
const path = require('path')

const PUBKEY_SZ = 32 // size of hypercore public keys
const CONTENT_SECRET_PATH = 'content_secret'

module.exports = function (storage, key, opts) {
  if (!Buffer.isBuffer(key) && !opts) {
    opts = key
    key = null
  }
  opts = opts || {}
  const internalFeedFactory = opts.core || hypercore
  delete opts.core

  const codec = opts.valueEncoding
  const hadEncode = codec && typeof codec.encode === 'function'
  const hadDecode = codec && typeof codec.decode === 'function'

  const feed = internalFeedFactory(storage, key, Object.assign({}, opts, {
    valueEncoding: 'binary'
  }))

  const getSecret = function (id, secret, opts, callback) {
    if (typeof opts === 'function') {
      callback = opts
      opts = {}
    }

    feed.get(id, opts, function (err, entry) {
      if (err) return callback(err)
      debugger
      callback(null, decrypt(entry, secret, codec))
    })
  }


  return new Proxy(feed, {
    get (target, prop, args) {
      switch (prop) {
        case 'appendEncrypted':
          return (secret, data, cb) => {
            feed.append(encrypt(data, secret, codec), cb)
          }
        //case 'get':
          //if (!hadDecode) return target[prop].bind(target)
          //get()
          //getBatch()
          //head()
        case 'getSecretbox':
          return
        // Proxy all poperty gets to original feed as default
        default:
          if (typeof target[prop] === 'function')
            return target[prop].bind(target)
          else
            return target[prop]
      }
    }
  })
}

function encrypt (data, encryptionKey, encode) {
  if (typeof encode === 'function') {
    data = encode(data)
  }
  if (!Buffer.isBuffer(data)) data = Buffer.from(data, 'utf-8')

  // Generate public nonce
  const nonceLen = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  const nonce = crypto.randomBytes(nonceLen)

  // Allocate buffer for the encrypted result.
  const encLen = data.length + sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES + nonceLen
  const encrypted = Buffer.alloc(encLen)

  // Insert the public nonce into the encrypted-message buffer at pos 0
  nonce.copy(encrypted)

  // Encrypt
  const n = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    encrypted.slice(nonceLen),
    data,
    null, // ADDITIONAL_DATA
    null, // always null according to sodium-native docs
    nonce,
    encryptionKey
  )

  assert.strictEqual(n, encLen - nonceLen, `Encryption error, expected encrypted bytes (${n}) to equal (${encLen - nonceLen}).`)
  return encrypted
}

function decrypt (buffer, encryptionKey, decode) {
  const nonceLen = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  const nonce = buffer.slice(0, nonceLen) // First part of the buffer
  const encrypted = buffer.slice(nonceLen) // Last part of the buffer

  const messageLen = buffer.length - sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES - nonceLen
  const message = Buffer.alloc(messageLen)

  const n = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    message,
    null, // always null
    encrypted,
    null, // ADDITIONAL_DATA
    nonce,
    encryptionKey
  )
  assert.strictEqual(n, messageLen, `Decryption error, expected decrypted bytes (${n}) to equal expected message length (${messageLen}).`)

  // Run originally provided encoder if any
  if (typeof decode === 'function')
    return decode(message, 0, message.length)
  else
    return message
}

function cryptoEncoder (encryptionKey, originalEncoder) {
  originalEncoder = codecs(opts.valueEncoding)

  return {
    encode(message, buffer, offset) {
      // Run originally provided encoder if any
      if (originalEncoder && typeof originalEncoder.encode === 'function') {
        message = originalEncoder.encode(message, buffer, offset)
      }
      // Normalize message to buffer
      if (!Buffer.isBuffer(message)) message = Buffer.from(message, 'utf-8')

      // Generate public nonce
      const npubLen = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
      const npub = crypto.randomBytes(npubLen) // is this random enough?

      // Allocate buffer for the encrypted result.
      const encLen = message.length + sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES + npubLen
      const encrypted = Buffer.alloc(encLen)

      // Insert the public nonce into the encrypted-message buffer at pos 0
      npub.copy(encrypted)

      // Encrypt
      const n = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        encrypted.slice(npubLen),
        message,
        null, // ADDITIONAL_DATA
        null, // always null according to sodium-native docs
        npub,
        encryptionKey
      )

      assert.equal(n, encLen-npubLen, `Encryption error, expected encrypted bytes (${n}) to equal (${encLen-npubLen}).`)
      return encrypted
    },

    decode(buffer, start, end) {
      const npubLen = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
      const npub = buffer.slice(0, npubLen) // First part of the buffer
      const encrypted = buffer.slice(npubLen) // Last part of the buffer

      const messageLen = buffer.length - sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES - npubLen
      const message = Buffer.alloc(messageLen)

      const n = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        message,
        null, // always null
        encrypted,
        null, // ADDITIONAL_DATA
        npub,
        encryptionKey
      )
      assert.equal(n, messageLen, `Decryption error, expected decrypted bytes (${n}) to equal expected message length (${messageLen}).`)

      // Run originally provided encoder if any
      if (originalEncoder && typeof originalEncoder.decode === 'function')
        return originalEncoder.decode(message, start, end)
      else
        return message
    }
  }
}
