# ciphercore
(Work in progress..)

ciphercore is a [proxy](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Proxy) factory
that extends [hypercore](https://github.com/mafintosh/hypercore) with the
following features:

* Transparently encrypts your content for cold-storage
* Introduces a new peer state (blind replicator)
* Should work as a drop-in replacement for existing hypercore dependents

```js

var ciphercore = require('ciphercore')

var feed = ciphercore('./my-first-dataset', {valueEncoding: 'utf-8'})

feed.append('hello')

// extended functionality
feed.blindKey // => Replication key
feed.key      // => Replication key + Decryption key

feed.internal // => the internal hypercore/proxy-target

```

Refer to the test for more info.

**TODO:**

* Test with compound-cores like hyperdrive && hyperdb
* Introduce dynamic coretype support for multifeed.
