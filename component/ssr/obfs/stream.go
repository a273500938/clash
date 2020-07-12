package obfs

import (
	"net"

	"github.com/Dreamacro/clash/common/pool"
)

// StreamConn wraps a stream-oriented net.Conn with obfs decoding/encoding
func StreamConn(c net.Conn, o Obfs) net.Conn {
	return &Conn{Conn: c, Obfs: o.initForConn()}
}

// Conn represents an obfs connection
type Conn struct {
	net.Conn
	Obfs
	buf    []byte
	offset int
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.buf != nil {
		n := copy(b, c.buf[c.offset:])
		c.offset += n
		if c.offset == len(c.buf) {
			c.buf = nil
		}
		return n, nil
	}

	buf := pool.Get(pool.RelayBufferSize)
	n, err := c.Conn.Read(buf)
	if err != nil {
		pool.Put(buf)
		return 0, err
	}
	decoded, sendback, err := c.Decode(buf[:n])
	if err != nil {
		return 0, err
	}
	if sendback {
		c.Write(nil)
		return 0, nil
	}
	n = copy(b, decoded)
	if len(decoded) > len(b) {
		c.buf = decoded
		c.offset = n
	}
	return n, err
}

func (c *Conn) Write(b []byte) (int, error) {
	encoded, err := c.Encode(b)
	if err != nil {
		return 0, err
	}
	_, err = c.Conn.Write(encoded)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
