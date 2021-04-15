package main

import (
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFF1Format(t *testing.T) {
	pt := "123456789"
	key16 := "rH8Fn/W1DxDeFkQBrWlaUQUF75bCVcr0h5XG6yY0y3E="
	twk := "39383736353433323130"

	decodedKey, err := base64.StdEncoding.DecodeString(key16)
	if err != nil {
		fmt.Println("key decode error:", err)
		return
	}

	fmt.Println(pt)
	ct := encrypt(pt, string(decodedKey), twk)
	fmt.Println(ct)

	decrypted := decrypt(ct, string(decodedKey), twk)
	fmt.Println(decrypted)
	assert.Equal(t, pt, decrypted, "!!! input NOT EQUAL TO decrypted")
}

func BenchmarkEncryptFormat(b *testing.B) {
	pt := "abcdefghijkl"
	key16 := "y9zHShe/o7I5jFa41JMEFA=="
	twk := "39383736353433323130"

	decoded, err := base64.StdEncoding.DecodeString(key16)
	if err != nil {
		fmt.Println("key decode error:", err)
		return
	}
	for n := 0; n < b.N; n++ {
		encrypt(pt, string(decoded), twk)
	}
}

func BenchmarkDecryptFormat(b *testing.B) {
	ct := "H*tq*Mn.&<r8"
	key16 := "y9zHShe/o7I5jFa41JMEFA=="
	twk := "39383736353433323130"

	decoded, err := base64.StdEncoding.DecodeString(key16)
	if err != nil {
		fmt.Println("key decode error:", err)
		return
	}

	for n := 0; n < b.N; n++ {
		decrypt(ct, string(decoded), twk)
	}
}
