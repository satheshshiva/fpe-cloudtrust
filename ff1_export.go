package main

import "C"
import (
	"crypto/aes"
	"crypto/cipher"
	"github.com/cloudtrust/fpe/fpe"
	"github.com/cloudtrust/fpe/fpe/format"
)

const blockSizeFF1 = 16

//export Encrypt
func Encrypt(_pt *C.char, _key *C.char, _tweak *C.char) *C.char {
	pt := C.GoString(_pt)
	generic := format.NewGenericPIIFormat()
	ke := []byte(C.GoString(_key))
	twk := []byte(C.GoString(_tweak))
	r := uint32(len(generic.CharToInt))
	encrypter, err := getFF1Encrypter(ke, twk, r)
	if err != nil {
		panic("couldn't create FF1 encrypter " + err.Error())
	}
	cipherText := format.Transform(pt, encrypter, generic)
	return C.CString(cipherText)
}

//export Decrypt
func Decrypt(_ct *C.char, _key *C.char, _tweak *C.char) *C.char {
	pt := C.GoString(_ct)
	generic := format.NewGenericPIIFormat()
	ke := []byte(C.GoString(_key))
	twk := []byte(C.GoString(_tweak))
	r := uint32(len(generic.CharToInt))
	encrypter, err := getFF1Decrypter(ke, twk, r)
	if err != nil {
		panic("couldn't create FF1 encrypter " + err.Error())
	}
	cipherText := format.Transform(pt, encrypter, generic)
	return C.CString(cipherText)
}

func main() {

}

//doing this for tests. In Go, the tests does not support CGO yet!
func encrypt(pt string, key string, tweak string) string {
	return C.GoString(Encrypt(C.CString(pt), C.CString(key), C.CString(tweak)))
}

func decrypt(pt string, key string, tweak string) string {
	return C.GoString(Decrypt(C.CString(pt), C.CString(key), C.CString(tweak)))
}

func getFF1Encrypter(key, tweak []byte, radix uint32) (cipher.BlockMode, error) {
	// Create AES Block used by FF1.
	var aesBlock, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create CBC mode used by FF1.
	var iv = make([]byte, blockSizeFF1)
	var cbcMode = cipher.NewCBCEncrypter(aesBlock, iv)

	// Create FF1 Encrypter
	var encrypter = fpe.NewFF1Encrypter(aesBlock, cbcMode, tweak, radix)

	return encrypter, nil
}

func getFF1Decrypter(key, tweak []byte, radix uint32) (cipher.BlockMode, error) {
	// Create AES Block used by FF1.
	var aesBlock, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create CBC mode used by FF1.
	var iv = make([]byte, blockSizeFF1)
	var cbcMode = cipher.NewCBCEncrypter(aesBlock, iv)

	// Create FF1 Decrypter
	var decrypter = fpe.NewFF1Decrypter(aesBlock, cbcMode, tweak, radix)

	return decrypter, nil
}
