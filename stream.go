package cipher

import (
	"crypto/cipher"
)

type Stream struct {
	DeStream cipher.Stream
	EnStream cipher.Stream
}

var _ Cipher = (*Stream)(nil)

func NewStream(deStream, enStream cipher.Stream) Cipher {
	return &Stream{deStream, enStream}
}

func (c *Stream) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	length := len(plaintext)
	ciphertext = make([]byte, length)
	c.EnStream.XORKeyStream(ciphertext[:], plaintext[:])
	return
}

func (c *Stream) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	length := len(ciphertext)
	plaintext = make([]byte, length)
	c.DeStream.XORKeyStream(plaintext[:], ciphertext[:])
	return
}
