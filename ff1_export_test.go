package main

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFF1GenericFormat(t *testing.T) {
	pt := "123456789"
	key32 := "rH8Fn/W1DxDeFkQBrWlaUQUF75bCVcr0h5XG6yY0y3E="
	twk := "39383736353433323130"

	fmt.Println(pt)
	ct := encryptForTests(pt, key32, twk)
	fmt.Println(ct)

	decrypted := decryptForTests(ct, key32, twk)
	fmt.Println(decrypted)
	assert.Equal(t, pt, decrypted, "!!! input NOT EQUAL TO decrypted")
}

func BenchmarkEncryptGeneric(b *testing.B) {
	pt := "abcdefghijkl"
	key16 := "y9zHShe/o7I5jFa41JMEFA=="
	twk := "39383736353433323130"
	for n := 0; n < b.N; n++ {
		encryptForTests(pt, key16, twk)
	}
}

func BenchmarkDecryptGeneric(b *testing.B) {
	ct := "H*tq*Mn.&<r8"
	key16 := "y9zHShe/o7I5jFa41JMEFA=="
	twk := "39383736353433323130"
	for n := 0; n < b.N; n++ {
		decryptForTests(ct, key16, twk)
	}
}
