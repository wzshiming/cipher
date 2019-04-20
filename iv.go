package cipher

import (
	"crypto/rand"
	"io"
)

// IV Size bytes
func IV(size int) []byte {
	iv := make([]byte, size)
	io.ReadFull(rand.Reader, iv)
	return iv
}
