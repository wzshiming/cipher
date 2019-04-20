package cipher

import (
	"crypto/cipher"
)

type Block struct {
	cipher.Block
}

var _ Cipher = (*Block)(nil)

func NewBlock(block cipher.Block) Cipher {
	return &Block{block}
}

// Encrypt Block encrypts data.
func (a *Block) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	length := len(plaintext)
	blockSize := a.Block.BlockSize()
	ciphertext = make([]byte, length)
	for i := 0; i < length; i += blockSize {
		a.Block.Encrypt(ciphertext[i:], plaintext[i:])
	}
	return
}

// Decrypt Block decrypts data.
func (a *Block) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	length := len(ciphertext)
	blockSize := a.Block.BlockSize()
	plaintext = make([]byte, length)
	for i := 0; i < length; i += blockSize {
		a.Block.Decrypt(plaintext[i:], ciphertext[i:])
	}
	return
}
