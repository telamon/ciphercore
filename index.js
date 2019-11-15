const hypercore = require('hypercore')
const debug = require('debug')('ciphercore')
// const codecs = require('codecs')
// const path = require('path')
const CryptoEncoder = require('./crypto-encoder.js')
const PUBKEY_SZ = 32 // size of hypercore public keys
const CONTENT_SECRET_PATH = 'content_secret'

module.exports = function (storage, key, opts = {}) {
  if (!Buffer.isBuffer(key) && !opts) {
    opts = key
    key = null
  }

  const contentSecret = opts.contentSecret
  delete opts.contentSecret

  const internalFeedFactory = opts.core || hypercore
  delete opts.core
  const encoder = new CryptoEncoder(contentSecret, opts.valueEncoding)

  const feed = internalFeedFactory(storage, key, Object.assign({}, opts, {
    valueEncoding: encoder
  }))

  /*
  const getSecret = function (id, secret, opts, callback) {
    if (typeof opts === 'function') {
      callback = opts
      opts = {}
    }

    feed.get(id, opts, function (err, entry) {
      if (err) return callback(err)
      callback(null, decrypt(entry, secret, codec))
    })
  } */

  // TODO: figure out how to interface the secret.
  // make some mock use-scenarios, gotta refresh my memory
  // on this code
  let initialized = false
  const initSecret = (cb) => {
    feed.ready(() => {
      if (initialized) return cb()
      debugger
      if (feed.secretKey && feed.length === 0) {
        // New empty writer
      } else if (!feed.secretKey) {
        // Blind mode
      }

      feed.key.length
      encoder.contentSecret
      initialized = true
      cb()
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
        case 'ready':
          return initSecret
        default:
          if (typeof target[prop] === 'function') {
            return (...args) => target[prop](...args)
          } else return target[prop]
      }
    }
  })
}

module.exports.CryptoEncoder = CryptoEncoder
