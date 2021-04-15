package main

import "C"
import (
	"crypto/aes"
	"crypto/cipher"
	"github.com/cloudtrust/fpe/fpe"
	"github.com/cloudtrust/fpe/fpe/format"
)

const blockSizeFF1 = 16

//export EncryptGenericPII
func EncryptGenericPII(pt *C.char, key *C.char, tweak *C.char) *C.char {
	return encrypt(pt, key, tweak, format.NewGenericPIIFormat())
}

//export DecryptGenericPII
func DecryptGenericPII(pt *C.char, key *C.char, tweak *C.char) *C.char {
	return decrypt(pt, key, tweak, format.NewGenericPIIFormat())
}

//export EncryptPANFullFpe
func EncryptPANFullFpe(pt *C.char, key *C.char, tweak *C.char) *C.char {
	return encrypt(pt, key, tweak, format.NewPANFullFpe())
}

//export DecryptPANFullFpe
func DecryptPANFullFpe(pt *C.char, key *C.char, tweak *C.char) *C.char {
	return decrypt(pt, key, tweak, format.NewPANFullFpe())
}

//export EncryptSSNFullFpe
func EncryptSSNFullFpe(pt *C.char, key *C.char, tweak *C.char) *C.char {
	return encrypt(pt, key, tweak, format.NewSSNFullFpe())
}

//export DecryptSSNFullFpe
func DecryptSSNFullFpe(pt *C.char, key *C.char, tweak *C.char) *C.char {
	return decrypt(pt, key, tweak, format.NewSSNFullFpe())
}

func encrypt(_pt *C.char, _key *C.char, _tweak *C.char, fpeformat *format.Fpeformat) *C.char {
	pt := C.GoString(_pt)
	ke := []byte(C.GoString(_key))
	twk := []byte(C.GoString(_tweak))
	r := uint32(len(fpeformat.CharToInt))
	encrypter, err := getFF1Encrypter(ke, twk, r)
	if err != nil {
		panic("couldn't create FF1 encrypter " + err.Error())
	}
	cipherText := format.Transform(pt, encrypter, fpeformat)
	return C.CString(cipherText)
}

func decrypt(_ct *C.char, _key *C.char, _tweak *C.char, fpeformat *format.Fpeformat) *C.char {
	pt := C.GoString(_ct)
	ke := []byte(C.GoString(_key))
	twk := []byte(C.GoString(_tweak))
	r := uint32(len(fpeformat.CharToInt))
	decrypter, err := getFF1Decrypter(ke, twk, r)
	if err != nil {
		panic("couldn't create FF1 decrypter " + err.Error())
	}
	cipherText := format.Transform(pt, decrypter, fpeformat)
	return C.CString(cipherText)
}

func main() {
	//empty main is needed for cgo to work
}

//doing this for tests. In Go, the tests does not support CGO yet!
func encryptForTests(pt string, key string, tweak string) string {
	return C.GoString(EncryptGenericPII(C.CString(pt), C.CString(key), C.CString(tweak)))
}

func decryptForTests(pt string, key string, tweak string) string {
	return C.GoString(DecryptGenericPII(C.CString(pt), C.CString(key), C.CString(tweak)))
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
