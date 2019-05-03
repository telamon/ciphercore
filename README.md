# hypercore-secure 
(Work in progress..)
hypercore compatible wrapper that provides transparent content encryption

```js

var hypercrypt = require('hypercore-secure')
var feed = hypercrypt('./my-first-dataset', {valueEncoding: 'utf-8'})

feed.append('hello') // identical API to hypercore

// extended functionality
feed.blindKey // => Replication key
feed.key      // => Replication key + Decryption key

feed.internal // => the internal hypercore
```

Refer to the test for more info.
