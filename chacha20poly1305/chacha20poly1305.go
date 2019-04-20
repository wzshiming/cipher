package chacha20poly1305

import (
	"golang.org/x/crypto/chacha20poly1305"
)

var Chacha20Poly1305 = chacha20poly1305.New
var XChacha20Poly1305 = chacha20poly1305.NewX
