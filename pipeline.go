package cipher

type Pipeline []Cipher

var _ Cipher = (Pipeline)(nil)

func NewPipeline(cipher ...Cipher) Cipher {
	return Pipeline(cipher)
}

// Encrypt Block encrypts data.
func (a Pipeline) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	for i := 0; i != len(a); i++ {
		v := a[i]
		plaintext, err = v.Encrypt(plaintext)
		if err != nil {
			return nil, err
		}
	}
	return plaintext, nil
}

// Decrypt Block decrypts data.
func (a Pipeline) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	for i := 0; i != len(a); i++ {
		v := a[len(a)-i-1]
		ciphertext, err = v.Decrypt(ciphertext)
		if err != nil {
			return nil, err
		}
	}
	return ciphertext, nil
}
