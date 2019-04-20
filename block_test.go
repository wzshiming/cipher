package cipher

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestBlock(t *testing.T) {

	key := []byte("hello")

	key, _ = PKCS7Padding(32).Encrypt(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	b := Block{block}
	src := []byte("hello data")
	data1, _ := PKCS7Padding(block.BlockSize()).Encrypt(src)

	d, _ := b.Encrypt(data1)
	data2, _ := b.Decrypt(d)

	dist, _ := PKCS7Padding(block.BlockSize()).Decrypt(data2)
	if !bytes.Equal(src, dist) {
		t.FailNow()
	}
}
