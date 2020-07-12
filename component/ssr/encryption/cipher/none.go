package cipher

import (
	"crypto/cipher"

	"github.com/Dreamacro/go-shadowsocks2/shadowstream"
)

type noneStream struct {
	cipher.Stream
}

type none struct{}

func (n *noneStream) XORKeyStream(dst, src []byte) {
	copy(dst, src)
}

func (n *none) IVSize() int {
	return 0
}

func (n *none) Encrypter(iv []byte) cipher.Stream {
	return new(noneStream)
}

func (n *none) Decrypter(iv []byte) cipher.Stream {
	return n.Encrypter(iv)
}

func None(key []byte) (shadowstream.Cipher, error) {
	return &none{}, nil
}
