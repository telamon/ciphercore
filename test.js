const test = require('tape')
const RAM = require('random-access-memory')
const hypercrypt = require('.')
const hypercore = require('hypercore')
const codecs = require('codecs')

function ramProxy(prefix) {
  return (path) => {
    return RAM(prefix + '/' + path)
  }
}

test("Transparent encryption", (t) => {
  t.plan(10)
  const feed = hypercrypt(RAM, {valueEncoding: 'utf8'})
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
  t.plan(22)
  // Create a new encrypted feed
  const feed = hypercrypt(ramProxy('author'), {valueEncoding: 'utf8'})
  feed.ready(() => {

    // Initialize blind replicate feed
    const blindFeed = hypercore(ramProxy('blind'), feed.blindKey, {valueEncoding: 'utf8'})
    blindFeed.ready(() => {

      // Initialize the trusted feed that will be able to read and replicate.
      const friendlyFeed = hypercore(ramProxy('trusted'), feed.id, {valueEncoding: 'utf8'})

      friendlyFeed.ready(() => {
        // Discovery keys should be the same regardless of read/write/replicate access.
        t.equal(feed.discoveryKey.toString('hex'), blindFeed.discoveryKey.toString('hex'), 'Discovery key should be universal #1')
        debugger
        t.equal(feed.discoveryKey.toString('hex'), friendlyFeed.discoveryKey.toString('hex'), 'Discovery key should be universal #2')

        const testMessage = 'hello hyperverse'

        feed.append(testMessage, (err) => {
          t.error(err)
          const s = feed.replicate()
          s.pipe(blindFeed.replicate()).pipe(s)
            .done((err) => {
              blindFeed.get(0, (err, entry) => {
                t.error(err)
                t.notEqual(entry, testMessage)
                t.error(err)
                const s = blindFeed.replicate()
                s.pipe(friendlyFeed.replicate()).pipe(s)
                  .done((err) => {
                    t.error(err)
                    friendlyFeed.get(0, (err, entry) => {
                      t.error(err)
                      t.equal(entry, testMessage)
                    })
                  })
              })
            })
        })
      })
    })
  })
})
