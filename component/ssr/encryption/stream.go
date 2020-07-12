package encryption

import (
	"crypto/rand"
	"io"
	"net"

	"github.com/Dreamacro/go-shadowsocks2/shadowstream"
)

// Conn wraps a net.Conn with ssr cipher along with its iv and key
type Conn struct {
	net.Conn
	shadowstream.Cipher
	r *shadowstream.Reader
	w *shadowstream.Writer

	iv  []byte
	key []byte
}

func NewConn(c net.Conn, ciph SSRStreamCipher) *Conn {
	iv := make([]byte, ciph.IVSize())
	if _, err := rand.Read(iv); err != nil {
		return nil
	}
	return &Conn{Conn: c, Cipher: ciph.Cipher, iv: iv, key: ciph.key}
}

func (c *Conn) initReader() error {
	if c.r == nil {
		iv := make([]byte, c.IVSize())
		if _, err := io.ReadFull(c.Conn, iv); err != nil {
			return err
		}
		c.r = shadowstream.NewReader(c.Conn, c.Decrypter(iv))
	}
	return nil
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.Read(b)
}

func (c *Conn) initWriter() error {
	if c.w == nil {
		iv := c.iv
		if _, err := c.Conn.Write(iv); err != nil {
			return err
		}
		c.w = shadowstream.NewWriter(c.Conn, c.Encrypter(iv))
	}
	return nil
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.Write(b)
}

// IV returns the iv of a Conn
func (c *Conn) IV() []byte {
	return c.iv
}
