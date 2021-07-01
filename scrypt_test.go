package go_scrypt_kdf

import (
	"testing"
)

func TestVerify(t *testing.T) {
	dhkey, err := Kdf([]byte("remove-before-flight"), DefaultParams)
	result, err := Verify(dhkey, []byte("remove-before-flight"))
	if !result {
		t.Error("Verify key failed: ", err)
	}
}
