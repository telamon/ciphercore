# hypercore-secure
(Experimental) hypercore compatible - that provides transparent content encryption

```js
var hypercrypt = require('hypercore-secure')
var feed = hypercore('./my-first-dataset', {valueEncoding: 'utf-8'})

feed.append('hello')
feed.append('world', function (err) {
  if (err) throw err
  feed.get(0, console.log) // prints hello
  feed.get(1, console.log) // prints world
})


feed.blindKey # => Replication key
feed.key      # => Read + Replication key
```
