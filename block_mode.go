package cipher

import (
	"crypto/cipher"
)

type BlockMode struct {
	DeBlockMode cipher.BlockMode
	EnBlockMode cipher.BlockMode
}

var _ Cipher = (*BlockMode)(nil)

func NewBlockMode(deBlockMode, enBlockMode cipher.BlockMode) Cipher {
	return &BlockMode{deBlockMode, enBlockMode}
}

func (c *BlockMode) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	length := len(plaintext)
	blockSize := c.EnBlockMode.BlockSize()
	if length%blockSize != 0 {
		return nil, ErrNotFullBlock
	}
	ciphertext = make([]byte, length)
	c.EnBlockMode.CryptBlocks(ciphertext[:], plaintext[:])
	return
}

func (c *BlockMode) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	length := len(ciphertext)
	blockSize := c.DeBlockMode.BlockSize()
	if length%blockSize != 0 {
		return nil, ErrNotFullBlock
	}
	plaintext = make([]byte, length)
	c.DeBlockMode.CryptBlocks(plaintext[:], ciphertext[:])
	return
}
