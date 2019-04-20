package cipher

import (
	"crypto/cipher"
)

// GCM Galois/Counter Mode
func GCM(b cipher.Block) (Cipher, error) {
	cip, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return NewAEAD(cip), nil
}

// CTR CounTeR Mode
func CTR(b cipher.Block) (Cipher, error) {
	return CTRWithIV(b, IV(b.BlockSize()))
}

// CBC Cipher Block Chaining Mode
func CBC(b cipher.Block) (Cipher, error) {
	return CBCWithIV(b, IV(b.BlockSize()))
}

// CFB Cipher FeedBack Mode
func CFB(b cipher.Block) (Cipher, error) {
	return CFBWithIV(b, IV(b.BlockSize()))
}

// OFB Output FeedBack Mode
func OFB(b cipher.Block) (Cipher, error) {
	return OFBWithIV(b, IV(b.BlockSize()))
}

// CTRWithIV CounTeR Mode
func CTRWithIV(b cipher.Block, iv []byte) (Cipher, error) {
	return NewStream(
		cipher.NewCTR(b, iv),
		cipher.NewCTR(b, iv),
	), nil
}

// CBCWithIV Cipher Block Chaining Mode
func CBCWithIV(b cipher.Block, iv []byte) (Cipher, error) {
	return NewBlockMode(
		cipher.NewCBCDecrypter(b, iv),
		cipher.NewCBCEncrypter(b, iv),
	), nil
}

// CFBWithIV Cipher FeedBack Mode
func CFBWithIV(b cipher.Block, iv []byte) (Cipher, error) {
	return NewStream(
		cipher.NewCFBDecrypter(b, iv),
		cipher.NewCFBDecrypter(b, iv),
	), nil
}

// OFBWithIV Output FeedBack Mode
func OFBWithIV(b cipher.Block, iv []byte) (Cipher, error) {
	return NewStream(
		cipher.NewOFB(b, iv),
		cipher.NewOFB(b, iv),
	), nil
}
