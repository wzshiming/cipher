package cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"testing"
)

var ciphers = []Cipher{}

var testdatas = [][]byte{
	IV(1),
	IV(15),
	IV(16),
	IV(17),
	IV(23),
	IV(24),
	IV(25),
	IV(31),
	IV(32),
	IV(33),
	IV(100),
}

func init() {
	for _, blockSize := range []int{16, 24, 32} {
		block, _ := aes.NewCipher(IV(blockSize))
		cipher := Pipeline{
			PKCS7Padding(block.BlockSize()),
			NewBlock(block),
		}
		ciphers = append(ciphers, cipher)
	}

	for _, blockSize := range []int{16, 24, 32} {
		block, _ := aes.NewCipher(IV(blockSize))
		aead, _ := cipher.NewGCM(block)
		cipher := Pipeline{
			NewAEAD(aead),
		}
		ciphers = append(ciphers, cipher)
	}

	for _, blockSize := range []int{16, 24, 32} {
		block, _ := aes.NewCipher(IV(blockSize))
		iv := IV(block.BlockSize())
		stream1 := cipher.NewCTR(block, iv)
		stream2 := cipher.NewCTR(block, iv)
		cipher := Pipeline{
			NewStream(stream1, stream2),
		}
		ciphers = append(ciphers, cipher)
	}

	for _, blockSize := range []int{16, 24, 32} {
		block, _ := aes.NewCipher(IV(blockSize))
		iv := IV(block.BlockSize())
		blockMode1 := cipher.NewCBCDecrypter(block, iv)
		blockMode2 := cipher.NewCBCEncrypter(block, iv)
		cipher := Pipeline{
			ZeroPadding(block.BlockSize()),
			NewBlockMode(blockMode1, blockMode2),
		}
		ciphers = append(ciphers, cipher)
	}
}

func TestCipher(t *testing.T) {
	for index, cipher := range ciphers {
		for _, testdata := range testdatas {
			t.Run(fmt.Sprintf("%d-block%d", index, len(testdata)), func(t *testing.T) {
				tmp, err := cipher.Encrypt(testdata)
				if err != nil {
					t.Error(err)
					return
				}
				if bytes.Equal(tmp, testdata) {
					t.Error("The encryption results did not change")
					return
				}
				sour, err := cipher.Decrypt(tmp)
				if err != nil {
					t.Error(err)
					return
				}

				if !bytes.Equal(testdata, sour) {
					t.Error("Decryption inconsistency")
					return
				}
			})
		}
	}
}
