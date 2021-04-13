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
func Encrypt(pt string, key string, tweak string) {
	fmt.Println("GO: Plain Text ", pt)
	generic := format.NewGenericPIIFormat()
	radix := len(generic.CharToInt)
	var toBeEncCnt int
	cs := generic.CharToInt
	toBeEnc := make([]uint16, len(pt))
	outliers := make(map[int]string)

	//form the outlying characters map
	for i, val := range pt {
		v := string(val)
		if j, ok := cs[v]; ok {
			toBeEnc[toBeEncCnt] = j
			toBeEncCnt++
		} else if generic.SkipOutliers {
			outliers[i] = v
		} else {
			panic(fmt.Sprintf("Value %s not in characterset", v))
		}
	}
	//trim the to Enc. the outliers would have left blanks
	toBeEnc = toBeEnc[0:toBeEncCnt]
	fmt.Println("pt", pt)
	fmt.Println("toBeEnc", toBeEnc)
	fmt.Println("outliers", outliers)

	//the actual encryption params
	ke := []byte(key)
	twk := []byte(tweak)
	r := uint32(radix)

	encrypter, err := getFF1Encrypter(ke, twk, r)
	if err != nil {
		panic("couldn't create FF1 encrypter " + err.Error())
	}

	//TODO is the numeral string coversion needed
	var src = fpe.NumeralStringToBytes(toBeEnc)
	var dst = make([]byte, len(src))
	//Encryption
	encrypter.CryptBlocks(dst, src)
	var tempCt = fpe.BytesToNumeralString(dst)
	fmt.Println("tempCt", tempCt)

	var ct string
	//transform int to char
	for i, val := range tempCt {
		//For this current position check whether outlying character exists
		if _, ok := outliers[i]; ok {
			ct += outliers[i]
		}
		ct += generic.IntToChar[val]
	}
	fmt.Println("ct", ct)
	//return C.CString(ct)
}

func main() {
	Encrypt("abcxjasdy1zad", "y9zHShe/o7I5jFa41JMEFA==", "asdd")
	//TestEncryptDecrypt()
}

//export TestEncryptDecrypt
func TestEncryptDecrypt() *C.char {
	name := C.CString("Gopher")
	fmt.Println(C.GoString(name))
	key := []byte("1234567890123456")
	tweak := []byte("tweak")
	radix := uint32(71)

	encrypter, err := getFF1Encrypter(key, tweak, radix)
	if err != nil {
		panic(err)
	}
	decrypter, err := getFF1Decrypter(key, tweak, radix)
	if err != nil {
		panic(err)
	}

	size := 71
	var out = make([]int, size)
	for i := 0; i < size; i++ {
		out[i] = i
	}

	var plaintext = make([]uint16, size)
	for i := 0; i < len(out); i++ {
		plaintext[i] = uint16(i)
	}

	// Encrypt random numeral string with random key
	var src = fpe.NumeralStringToBytes(plaintext)
	var dst = make([]byte, len(src))
	encrypter.CryptBlocks(dst, src)
	var ciphertext = fpe.BytesToNumeralString(dst)
	fmt.Println(ciphertext)

	// Decrypt ciphertext
	src = fpe.NumeralStringToBytes(ciphertext)
	decrypter.CryptBlocks(dst, src)
	var decrypted = fpe.BytesToNumeralString(dst)
	fmt.Println("plain", plaintext)
	fmt.Println("decrypted", decrypted)
	return C.CString("Done")
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
