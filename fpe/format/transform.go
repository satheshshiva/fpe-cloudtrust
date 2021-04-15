package format

import "C"
import (
	"crypto/cipher"
	"fmt"
	"github.com/cloudtrust/fpe/fpe"
)

// Transform Encrypts or Decypts the given string based on the given fpe fpeformat
// Three steps involved
// Step 1: Remove the outlying characters and form the outlying characters map and toBeProcessed array
// Step 2: Encrypt or Decypt the toBeProcessed array
// Step 3: Combine both the processed array and outliers map

func Transform(ip string, encdec cipher.BlockMode, fpeformat *Fpeformat) string {
	var toBeEncCnt int
	cs := fpeformat.CharToInt
	toBeProcessed := make([]uint16, len(ip))
	outliers := make(map[int]string)
	ipRune := []rune(ip)

	// Step 1: Remove the outlying characters and form the outlying characters map and toBeProcessed array
	for i := 0; i < len(ipRune); i++ {
		v := string(ipRune[i])
		if j, ok := cs[v]; ok {
			toBeProcessed[toBeEncCnt] = j
			toBeEncCnt++
		} else if fpeformat.SkipOutliers {
			outliers[i] = v
		} else {
			panic(fmt.Sprintf("Value %s not in characterset", v))
		}
	}

	// Step 2: Encrypt or Decypt the toBeProcessed array
	//trim the to Enc. the outliers would have left blanks
	toBeProcessed = toBeProcessed[0:toBeEncCnt]
	//TODO is the numeral string conversion needed
	var src = fpe.NumeralStringToBytes(toBeProcessed)
	var dst = make([]byte, len(src))
	//Encryption
	encdec.CryptBlocks(dst, src)
	var tempOp = fpe.BytesToNumeralString(dst)
	var op string

	// Step 3: Combine both the processed array and outliers map
	// forming the cipher text from encrypted numerals
	//the encrypted will have numeral string. replace the integers with actual characters from character set
	j := 0
	for i := 0; i < len(tempOp)+len(outliers); i++ {
		//For this current position check whether outlying character exists
		if _, ok := outliers[i]; ok {
			op += outliers[i]
		} else {
			op += fpeformat.IntToChar[tempOp[j]]
			j++
		}
	}
	return op
}
