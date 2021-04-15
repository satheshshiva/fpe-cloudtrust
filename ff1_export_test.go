package main

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFF1Format(t *testing.T) {
	pt := "abcdefghijkl"
	key16 := "y9zHShe/o7I5jFa41JMEFA=="
	twk := "39383736353433323130"

	fmt.Println(pt)
	ct := encrypt(pt, key16, twk)
	fmt.Println(ct)

	decrypted := decrypt(ct, key16, twk)
	fmt.Println(decrypted)
	assert.Equal(t, pt, decrypted, "!!! input NOT EQUAL TO decrypted")
}

func BenchmarkEncryptFormat(b *testing.B) {
	pt := "abcdefghijkl"
	key16 := "y9zHShe/o7I5jFa41JMEFA=="
	twk := "39383736353433323130"

	for n := 0; n < b.N; n++ {
		encrypt(pt, key16, twk)
	}
}

func BenchmarkDecryptFormat(b *testing.B) {
	ct := "H*tq*Mn.&<r8"
	key16 := "y9zHShe/o7I5jFa41JMEFA=="
	twk := "39383736353433323130"

	// run the Fib function b.N times
	for n := 0; n < b.N; n++ {
		decrypt(ct, key16, twk)
	}
}
