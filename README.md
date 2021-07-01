# go-scrypt-kdf

This package is a port of the `scrypt-kdf` nodejs library to Go.

## Usage

```go
package main

import (
    gsk "github.com/gryffyn/go-scrypt-kdf"
)

func main() {
    derivedKey, err := gsk.Kdf("password", gsk.DefaultParams)
    valid := gsk.Verify(derivedKey, "password") // true
    invalid := gsk.Verify(derivedKey, "not_password") // false
}
```

## Format

Outputs a 96 byte `[]byte`. Uses the [Tarsnap format](https://github.com/Tarsnap/scrypt/blob/master/FORMAT).
```
scrypt encrypted data format
----------------------------

offset	length
0	6	"scrypt"
6	1	scrypt data file version number (== 0)
7	1	log2(N) (must be between 1 and 63 inclusive)
8	4	r (big-endian integer; must satisfy r * p < 2^30)
12	4	p (big-endian integer; must satisfy r * p < 2^30)
16	32	salt
48	16	first 16 bytes of SHA256(bytes 0 .. 47)
64	32	HMAC-SHA256(bytes 0 .. 63)
96	X	data xor AES256-CTR key stream generated with nonce == 0
96+X	32	HMAC-SHA256(bytes 0 .. 96 + (X - 1))
```

## License

Original repo [license](https://github.com/chrisveness/scrypt-kdf).

Licensed MIT, see `LICENSE` for details.