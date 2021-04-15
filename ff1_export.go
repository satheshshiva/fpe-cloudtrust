package main

import "C"
import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"github.com/cloudtrust/fpe/fpe"
	"github.com/cloudtrust/fpe/fpe/format"
)

const blockSizeFF1 = 16

type process int

const (
	encrypt process = iota
	decrypt
)

//export EncryptGenericPII
func EncryptGenericPII(pt *C.char, key *C.char, tweak *C.char) *C.char {
	return doProcess(encrypt, pt, key, tweak, format.NewGenericPIIFormat())
}

//export DecryptGenericPII
func DecryptGenericPII(pt *C.char, key *C.char, tweak *C.char) *C.char {
	return doProcess(decrypt, pt, key, tweak, format.NewGenericPIIFormat())
}

//export EncryptPANFullFpe
func EncryptPANFullFpe(pt *C.char, key *C.char, tweak *C.char) *C.char {
	return doProcess(encrypt, pt, key, tweak, format.NewPANFullFpe())
}

//export DecryptPANFullFpe
func DecryptPANFullFpe(pt *C.char, key *C.char, tweak *C.char) *C.char {
	return doProcess(decrypt, pt, key, tweak, format.NewPANFullFpe())
}

//export EncryptSSNFullFpe
func EncryptSSNFullFpe(pt *C.char, key *C.char, tweak *C.char) *C.char {
	return doProcess(encrypt, pt, key, tweak, format.NewSSNFullFpe())
}

//export DecryptSSNFullFpe
func DecryptSSNFullFpe(pt *C.char, key *C.char, tweak *C.char) *C.char {
	return doProcess(decrypt, pt, key, tweak, format.NewSSNFullFpe())
}

func doProcess(proc process, _txt *C.char, _key *C.char, _tweak *C.char, fpeformat *format.Fpeformat) *C.char {
	txt := C.GoString(_txt)
	ke, err := base64.StdEncoding.DecodeString(C.GoString(_key))
	if err != nil {
		panic("key decode error:" + err.Error())
	}

	twk := []byte(C.GoString(_tweak))
	r := uint32(len(fpeformat.CharToInt))
	var op string
	var crypto cipher.BlockMode

	//create key cipher
	aesBlock, err := aes.NewCipher(ke)
	if err != nil {
		panic("Couldn't create key:" + err.Error())
	}

	// Create CBC mode used by FF1.
	var iv = make([]byte, blockSizeFF1)
	var cbcMode = cipher.NewCBCEncrypter(aesBlock, iv)

	if proc == encrypt {
		crypto = fpe.NewFF1Encrypter(aesBlock, cbcMode, twk, r)
	} else {
		crypto = fpe.NewFF1Decrypter(aesBlock, cbcMode, twk, r)
	}
	//actual process happens below. outlying characters +  encryption or decryption.
	op = format.Transform(txt, crypto, fpeformat)

	return C.CString(op)
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
