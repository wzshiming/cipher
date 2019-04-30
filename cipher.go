package cipher

import (
	"errors"
)

type Cipher interface {
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
	Decrypt(ciphertext []byte) (plaintext []byte, err error)
}

var ErrNotFullBlock = errors.New("input not full block")
