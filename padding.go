package cipher

import (
	"bytes"
	"errors"
)

var (
	ErrNotBlock = errors.New("cipher: data is not a multiple of the block size")
)

type PKCS7Padding int

func NewPKCS7Padding(i int) Cipher {
	return PKCS7Padding(i)
}

var _ Cipher = (*PKCS7Padding)(nil)

func (p PKCS7Padding) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	padding := int(p) - len(plaintext)%int(p)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	ciphertext = append(plaintext, padtext...)
	return
}

func (p PKCS7Padding) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	length := len(ciphertext)
	if length%int(p) != 0 {
		return nil, ErrNotBlock
	}
	unpadding := int(ciphertext[length-1])
	if unpadding > length {
		return nil, ErrNotBlock
	}
	plaintext = ciphertext[:length-unpadding]
	return
}

type ZeroPadding int

func NewZeroPadding(i int) Cipher {
	return ZeroPadding(i)
}

var _ Cipher = (*ZeroPadding)(nil)

func (p ZeroPadding) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	padding := int(p) - len(plaintext)%int(p)
	padtext := make([]byte, padding)
	ciphertext = append(plaintext, padtext...)
	return
}

func (p ZeroPadding) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	plaintext = bytes.TrimFunc(ciphertext, func(r rune) bool {
		return r == 0
	})
	return
}
