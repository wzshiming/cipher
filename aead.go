package cipher

import (
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// AEAD packaging to simplify operations
type AEAD struct {
	cipher.AEAD
}

var _ Cipher = (*AEAD)(nil)

func NewAEAD(aead cipher.AEAD) Cipher {
	return &AEAD{aead}
}

// Encrypt AEAD encrypts data.
func (a *AEAD) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	nonce := make([]byte, a.AEAD.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	return a.AEAD.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt AEAD decrypts data.
func (a *AEAD) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	nonceSize := a.AEAD.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrNotFullBlock
	}
	return a.AEAD.Open(nil,
		ciphertext[:nonceSize],
		ciphertext[nonceSize:],
		nil,
	)
}
