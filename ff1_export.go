package main

import "C"
import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
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
	//pt := ";kmfglskdnfg v;df123m sdlafkmlkdsf;lke456jr sfdlmsf;lnefnewr;f742knmerf"
	pt := ";kmfglskdnfg v;df123m sdla✅fkmlkdsf;lke456jr sfdl✅msf;lnefnewr;f742knmerf" //fail
	//pt := "✅ke456jr sfdlmsf"	//fail
	fmt.Println(pt)
	ct := Encrypt(C.CString(pt), C.CString("y9zHShe/o7I5jFa41JMEFA=="), C.CString("39383736353433323130"))
	cipherText := C.GoString(ct)
	fmt.Println(cipherText)

	decrypted := Decrypt(ct, C.CString("y9zHShe/o7I5jFa41JMEFA=="), C.CString("39383736353433323130"))
	_decrypted := C.GoString(decrypted)
	fmt.Println(_decrypted)
	if pt == _decrypted {
		fmt.Println("INPUT = DECRYPTED")
	} else {
		panic("!INPUT NOT DECRYPTED")
	}
	//TestEncryptDecrypt()
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
