const sodium = require('sodium-universal')

class CryptoEncoder {
  constructor (secret, codec) {
    this.secret = secret
    this.codec = codec
  }

  get hasSubDecoder () { return this.codec && typeof this.codec.decode === 'function' }
  get hasSubEncoder () { return this.codec && typeof this.codec.encode === 'function' }

  encode (message, buffer, offset) {
    // Run originally provided encoder if any
    if (this.hasSubEncoder) {
      message = this.codec.encode(message, buffer, offset)
    }
    return this.secret ? CryptoEncoder.encrypt(message, this.secret) : message
  }

  decode (buffer, start, end) {
    // TODO: warning i'm ignoring start & end here cause i cannot find
    // a single reference that uses it
    const message = this.secret ? CryptoEncoder.decrypt(buffer, this.secret) : buffer
    // Run originally provided encoder if any
    if (this.hasSubDecoder) return this.codec.decode(message)
    else return message
  }

  /**
   * Encryption methods
   **/
  static encrypt (data, encryptionKey) {
    if (!Buffer.isBuffer(data)) data = Buffer.from(data, 'utf-8')

    // Generate public nonce
    const nonceLen = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    const nonce = Buffer.alloc(nonceLen)
    sodium.randombytes_buf(nonce)

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

    if (n !== encLen - nonceLen) throw new Error(`Encryption error, expected encrypted bytes (${n}) to equal (${encLen - nonceLen}).`)
    return encrypted
  }

  static decrypt (buffer, encryptionKey) {
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

    if (n !== messageLen) throw new Error(`Decryption error, expected decrypted bytes (${n}) to equal expected message length (${messageLen}).`)
    return message
  }
}

module.exports = CryptoEncoder
