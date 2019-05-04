const test = require('tape')
const RAM = require('random-access-memory')
const ciphercore = require('.')
const hypercore = require('hypercore')
const codecs = require('codecs')
const pump = require('pump')

function ramProxy(prefix) {
  return (path) => {
    return RAM(prefix + '/' + path)
  }
}

test("Transparent encryption", (t) => {
  t.plan(10)
  const feed = ciphercore(RAM, {valueEncoding: 'utf8'})
  t.ok(feed.key.length > 32, 'should expose the read-key')
  t.ok(feed.blindKey, 'should expose a new key to use for blind-replication')
  t.ok(feed.internal, 'should expose internal feed')
  feed.ready(() => {
    t.notEqual(feed.key.toString('hex'), feed.blindKey.toString('hex'), "Blind and public key should differ")
    t.equal(feed.blindKey.toString('hex'), feed.internal.key.toString('hex'),
      'Internal feed should only be aware of the blind replication-key')

    const testData  = 'Bobby was a shy little sheep'

    // Append some data
    feed.append(testData, (err) => {
      t.error(err)
      // Verify transparent encryption
      // by temporarily disabling the transparent decryption
      let encrypter = feed.internal._codec
      feed.internal._codec = codecs('utf8') // temporariy set to utf8 decoder

      feed.internal.get(0, (err, entry) => {
        t.error(err)
        t.notEqual(entry, testData, 'content should have been encrypted')
        feed.internal._codec = encrypter // Restore the encrypting decoder.

        // Verify transparent decryption
        feed.get(0, (err, entry) => {
          t.error(err)
          t.equal(entry, testData, 'content transparently decrypted')
          t.end()
        })
      })
    })
  })
})

test("Blind replication", (t) => {
  t.plan(12)
  // Create a new encrypted feed
  const feed = ciphercore(ramProxy('author'), {valueEncoding: 'utf8'})
  feed.ready(() => {

    // Initialize blind replicate feed by providing it `feed.blindKey` and using plain `hypercore` instance
    // Note: calling ciphercore with only a blind-key will cause a regular hypercore instance to be returned.
    const blindFeed = hypercore(ramProxy('blind'), feed.blindKey, {valueEncoding: 'utf8'})
    blindFeed.ready(() => {

      // Initialize the trusted feed that will be able to read and replicate.
      const friendlyFeed = ciphercore(ramProxy('trusted'), feed.key, {valueEncoding: 'utf8'})

      friendlyFeed.ready(() => {
        // Discovery keys should be the same regardless of read/write/replicate access.
        t.equal(feed.discoveryKey.toString('hex'), blindFeed.discoveryKey.toString('hex'), 'Discovery key should be universal #1')
        t.equal(feed.discoveryKey.toString('hex'), friendlyFeed.discoveryKey.toString('hex'), 'Discovery key should be universal #2')

        t.equal(feed.key.toString('hex'), friendlyFeed.key.toString('hex'), 'Read key should have been nicely parsed and loaded')

        // Same goes for the regular public keys used by hypercore-protocol for transport encryption
        t.equal(feed.internal.key.toString('hex'), blindFeed.key.toString('hex'), 'Replication key should be universal #1')
        t.equal(feed.internal.key.toString('hex'), friendlyFeed.internal.key.toString('hex'), 'Replication key should be universal #2')

        const testMessage = 'hello hyperverse'
        // Test replication using Author -> BlindRepl -> Friend
        feed.append(testMessage, (err) => {
          t.error(err)
          const s = feed.replicate()
          pump(s, blindFeed.replicate(), s, (err) => {
            t.error(err)
            blindFeed.get(0, (err, entry) => {
              t.error(err)
              t.notEqual(entry, testMessage, 'Blind replicator sees encrypted data')

              const s = blindFeed.replicate()
              pump(s, friendlyFeed.replicate(), s, (err) => {
                t.error(err)
                friendlyFeed.get(0, (err, entry) => {
                  t.error(err)
                  t.equal(entry, testMessage, 'Friendly feed sees derypted data')
                  t.end()
                })
              })
            })
          })
        })
      })
    })
  })
})

test.only('Content-secret persistence', (t) => {
  t.plan(100)
  const feed = ciphercore(ramProxy('saveTest'), {valueEncoding: 'utf8'})
  feed.ready(() => {
    feed.append('Hello', (err) => {
      t.error(err)
      const secretKey = feed.secretKey
      const publicKey = feed.internal.key
      const contentKey = feed.contentSecret

      const persisted = ciphercore(ramProxy('saveTest'), {valueEncoding: 'utf8'})
      persisted.ready(()=> {
        t.equal(secretKey.toString('hex'), persisted.secretKey.toString('hex'), 'signing secret loaded successfully')
        t.equal(publicKey.toString('hex'), persisted.internal.key.toString('hex'), 'replication secret loaded successfully')
        t.equal(contentKey.toString('hex'), persisted.contentSecret.toString('hex'), 'content secret loaded successfully')
        persisted.get(0, (err, entry) => {
          t.error(err)
          t.equal(entry, 'Hello')
          t.end()
        })
      })
    })
  })
})
