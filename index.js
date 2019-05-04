const hypercore = require('hypercore')
const crypto = require('hypercore-crypto')
const sodium = require('sodium-universal')
const debug = require('debug')('ciphercore')
const codecs = require('codecs')
const assert = require('assert')
const raf = require('random-access-file')
const path = require('path')

const PUBKEY_SZ = 32 // size of hypercore public keys
const CONTENT_SECRET_PATH = 'content_secret'

module.exports = function (storage, key, opts) {
  if (!Buffer.isBuffer(key) && !opts) {
    opts = key
    key = null
  }

  let secretKey = null
  let contentSecret = null

  if (typeof storage === 'string') {
    const rootPath = storage
    createStorage = (p) => {
      return raf(path.join(rootPath, p))
    }
  }
  if (typeof storage !== 'function') throw new Error('Storage should be a function or string')

  // TODO: check storage for keys before trying to initialize.

  // If pubkey is available try to extract contentKey
  if (key) {
    if (typeof key === 'string') key = new Buffer(key,'hex') // Assume key is a hexstring

    // [key, contentSecret] = parseReadKey(key) // TODO: fancy destructuring dosen't work for some reason..
    const r = parseReadKey(key)
    key = r[0]
    contentSecret = r[1]
  }

  // |-----------+-----------+---------------+--------------------------------------|
  // | secretKey | publicKey | contentSecret | Mode of operation                    |
  // |-----------+-----------+---------------+--------------------------------------|
  // | have      | have      | have          | Writer                               |
  // | have      | extract   | have          |                                      |
  // |-----------+-----------+---------------+--------------------------------------|
  // | have      | have      | n/a           | Faulty writer (throw) theoretically  |
  // | have      | extract   | n/a           | you can write unencrypted entries... |
  // |-----------+-----------+---------------+--------------------------------------|
  // | n/a       | have      | n/a           | Replicator (return hypercore())      |
  // |-----------+-----------+---------------+--------------------------------------|
  // | n/a       | have      | have          | Reader                               |
  // |-----------+-----------+---------------+--------------------------------------|
  // | n/a       | n/a       | n/a           | Generate new feed & new keys         |
  // |-----------+-----------+---------------+--------------------------------------|
  // | n/a       | n/a       | opts          | Generate new feed use provided       |
  // |           |           |               | contentSecret for encryption         |
  // |-----------+-----------+---------------+--------------------------------------|
  //
  // Note: secretKey embeds a copy of the publicKey and can be extracted
  //

  if (!key && secretKey) {
    // TODO: Sodium extract pubkey from signing pair
  }

  if (key && secretKey && !contentSecret) throw new Error("Mixing plain and encrypted feed entries is not yet supported")

  // Become a blind-replicator, return a plain hypercore without encryption/decryption support.
  if (key && !contentSecret) return hypercore(storage, key, opts)

  // Generate new keypair
  if (!key && !secretKey) {
    let pair = crypto.keyPair()
    key =  pair.publicKey // A.k.a (blind) replication key
    secretKey = pair.secretKey // Signing key
    contentSecret = opts.contentSecret || crypto.randomBytes(16) // Read-access
    // TODO: persist contentSecret to storage
    debug(`Initialized new feed`)
  }

  const encryptionKey =  hashEncryptionKey(key, contentSecret)

  const originalEncoder = codecs(opts.valueEncoding)

  const cryptoEncoder = {
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
      if (originalEncoder && typeof originalEncoder.decode === 'function') {
        return originalEncoder.decode(message, start, end)
      } else
        return message
    }
  }

  const feed = hypercore(storage, key, Object.assign({},opts, {valueEncoding: cryptoEncoder, secretKey}))

  debug(`- New feed instance ---\n` +
    `blindReplKey: \t${key.toString('hex').substr(0,8)}\n` +
    `discoveryKey: \t${feed.discoveryKey.toString('hex').substr(0,8)}\n` +
    `writingKey: \t\t${secretKey && secretKey.toString('hex').substr(0,8)}\n` +
    `readKey: \t\t${makeReadKey(key, contentSecret).toString('hex').substr(0,8)}\n` +
    `contentSecret: \t${contentSecret.toString('hex').substr(0,8)}\n` +
    `encryptionKey: \t${hashEncryptionKey(key, contentSecret).toString('hex').substr(0,8)}\n`)


  return new Proxy(feed, {
    get (target, prop, args) {
      switch (prop) {
        case 'internal':
          return feed
        case 'key':
          return makeReadKey(key, contentSecret)
        case 'blindKey':
          return feed.key

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

function hashEncryptionKey (pubKey, secret) {
  const len = 2048 // TODO: Not sure about this number
  const key = Buffer.alloc(len)
  sodium.crypto_pwhash(
   key,
    Buffer.from(secret),
    pubKey,
    8,
    sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    1
  )
  return key
}

function makeReadKey(pubKey, secret) {
  const readKey = Buffer.alloc(PUBKEY_SZ + secret.length)
  pubKey.copy(readKey)
  secret.copy(readKey, PUBKEY_SZ)
  return readKey
}
module.exports.makeReadKey = makeReadKey

function parseReadKey(readKey) {
  if (readKey.length <= PUBKEY_SZ) return [readKey] // No secret available

  const pubKey = readKey.slice(0, PUBKEY_SZ)
  const secret = readKey.slice(PUBKEY_SZ)
  return [pubKey, secret]
}
module.exports.parseReadKey = parseReadKey

// expose the path constant for easier random-access diversion
// for those who would like to store their encryption secrets separately
// from the core.
module.exports.CONTENT_SECRET_PATH = CONTENT_SECRET_PATH
