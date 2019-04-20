package cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func TestBlockMode(t *testing.T) {
	key := []byte("hello")

	key, _ = PKCS7Padding(32).Encrypt(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	iv := IV(block.BlockSize())
	stream1 := cipher.NewCBCDecrypter(block, iv)
	stream2 := cipher.NewCBCEncrypter(block, iv)

	b := BlockMode{stream1, stream2}
	src := []byte("hello data 11111111111")
	data1, _ := PKCS7Padding(block.BlockSize()).Encrypt(src)

	d, _ := b.Encrypt(data1)
	data2, _ := b.Decrypt(d)

	dist, _ := PKCS7Padding(block.BlockSize()).Decrypt(data2)
	if !bytes.Equal(src, dist) {
		t.FailNow()
	}
}
