package encryption

import (
	"crypto/md5"
	"net"
	"strings"

	"github.com/Dreamacro/clash/component/ssr/encryption/cipher"
	"github.com/Dreamacro/go-shadowsocks2/core"
	"github.com/Dreamacro/go-shadowsocks2/shadowstream"
)

// SSRStreamCipher is stream cipher for ssr
type SSRStreamCipher struct {
	shadowstream.Cipher
	key []byte
}

// Key returns the key of a cipher
func (ciph *SSRStreamCipher) Key() []byte {
	return ciph.key
}

// KeySize returns the size of key
func (ciph *SSRStreamCipher) KeySize() int {
	return len(ciph.key)
}

// StreamConn returns a Conn with net.Conn and ssr cipher
func (ciph *SSRStreamCipher) StreamConn(c net.Conn) net.Conn {
	return NewConn(c, *ciph)
}

// PacketConn returns a PacketConn with net.PacketConn and ssr cipher
func (ciph *SSRStreamCipher) PacketConn(c net.PacketConn) net.PacketConn {
	return NewPacketConn(c, *ciph)
}

var streamList = map[string]struct {
	KeySize int
	New     func(key []byte) (shadowstream.Cipher, error)
}{
	"RC4-MD5":       {16, shadowstream.RC4MD5},
	"AES-128-CTR":   {16, shadowstream.AESCTR},
	"AES-192-CTR":   {24, shadowstream.AESCTR},
	"AES-256-CTR":   {32, shadowstream.AESCTR},
	"AES-128-CFB":   {16, shadowstream.AESCFB},
	"AES-192-CFB":   {24, shadowstream.AESCFB},
	"AES-256-CFB":   {32, shadowstream.AESCFB},
	"CHACHA20-IETF": {32, shadowstream.Chacha20IETF},
	"XCHACHA20":     {32, shadowstream.Xchacha20},
	"NONE":          {16, cipher.None},
}

// PickCipher picks a cipher for ssr conn
func PickCipher(name string, key []byte, password string) (core.Cipher, error) {
	name = strings.ToUpper(name)

	if choice, ok := streamList[name]; ok {
		if len(key) == 0 {
			key = Kdf(password, choice.KeySize)
		}
		if len(key) != choice.KeySize {
			return nil, shadowstream.KeySizeError(choice.KeySize)
		}
		ciph, err := choice.New(key)
		return &SSRStreamCipher{Cipher: ciph, key: key}, err
	}

	return nil, core.ErrCipherNotSupported
}

// Kdf is key-derivation function from original Shadowsocks
func Kdf(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}
