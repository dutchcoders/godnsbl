# godnsbl
Interface for querying DNSBL using GO.

## Usage
```
package main

import (
    "github.com/dutchcoders/godnsbl"
    "net"
)

func main() {
    ip := net.ParseIP("1.2.3.4")

    var result dnsbl.Result
    var err error
    
    if result, err := dnsbl.Check(test.blacklist, net.ParseIP(test.got)); err != nil {
        panic(err)
    }

    fmt.Println("%#v", result)
}
```

## Contributions

Contributions are welcome.

## Creators

**Remco Verhoef**
- <https://twitter.com/remco_verhoef>
- <https://twitter.com/dutchcoders>

## Copyright and license

Code and documentation copyright 2011-2014 Remco Verhoef.

Code released under [the MIT license](LICENSE).

