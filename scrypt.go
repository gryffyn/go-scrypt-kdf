// Package go_scrypt_kdf implements the scrypt-kdf NPM package in Go.
package go_scrypt_kdf

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math"

	"golang.org/x/crypto/scrypt"
)

// Params defines the parameters for the scrypt algorithm.
type Params struct {
	LogN uint8
	R    uint32
	P    uint32
}

// DefaultParams are a set of sane defaults for scrypt.
var DefaultParams = Params{LogN: 15, R: 8, P: 1}

// Kdf derives a key from password with the given parameters.
func Kdf(password []byte, params Params) ([]byte, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return skdfWrite(password, salt, params.LogN, params.R, params.P)
}

// Verify checks the given key against an attempted password.
func Verify(key, attempt []byte) (bool, error) {
	if len(key) != 96 {
		return false, errors.New("invalid key")
	}

	keyPar := skdfRead(key)
	attemptKey, err := skdfWrite(attempt, keyPar.Salt, keyPar.LogN, keyPar.R, keyPar.P)
	if subtle.ConstantTimeCompare(key, attemptKey) == 1 {
		if err == nil {
			return true, nil
		}
	}
	return false, err
}

func skdfWrite(pw []byte, salt []byte, LogN uint8, r uint32, p uint32) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Grow(96) // set buffer to 96 bytes

	buf.WriteString("scrypt") // writes initial "scrypt" header

	buf.Write([]byte{0}) // tbh i've no clue what this is. version?

	buf.Write([]byte{LogN}) // LogN is som

	rByte := make([]byte, 4)
	binary.LittleEndian.PutUint32(rByte, r)
	buf.Write(rByte) // converts the uint32 to []byte and writes it

	pByte := make([]byte, 4)
	binary.BigEndian.PutUint32(pByte, p)
	buf.Write(pByte) // same as above

	buf.Write(salt) // writes 32 byte salt

	check48 := crypto.SHA256.New()
	check48.Write(buf.Bytes())
	buf.Write(check48.Sum(nil)[:16]) // writes first 16 bytes of sha256 checksum of first 48 bytes of buf

	dhkey, err := scrypt.Key(pw, salt, int(math.Round(math.Pow(2, float64(LogN)))), int(r), int(p), 64)
	check64 := hmac.New(crypto.SHA256.New, dhkey[32:]) // second 32 bytes of hmac
	check64.Write(buf.Bytes())
	buf.Write(check64.Sum(nil))

	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type skdfParams struct {
	Scrypt   []byte // 6
	V        uint8  // 1
	LogN     uint8  // 1
	R        uint32 // 4
	P        uint32 // 4
	Salt     []byte // 32
	Checksum []byte // 16
	HMACHash []byte // 32
}

func skdfRead(hash []byte) skdfParams {
	return skdfParams{
		Scrypt:   hash[:6],                             // 6
		V:        hash[6],                              // 7
		LogN:     hash[7],                              // 8
		R:        binary.BigEndian.Uint32(hash[8:12]),  // 12
		P:        binary.BigEndian.Uint32(hash[12:16]), // 16
		Salt:     hash[16:48],                          // 48
		Checksum: hash[48:64],                          // 64
		HMACHash: hash[64:96],                          // 96
	}
}
