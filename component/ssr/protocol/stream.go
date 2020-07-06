package protocol

import (
	"net"

	"github.com/Dreamacro/clash/common/pool"
)

// StreamConn wraps a stream-oriented net.Conn with protocol decoding/encoding
func StreamConn(c net.Conn, p Protocol) net.Conn {
	p.init()
	return &Conn{Conn: c, Protocol: p}
}

// Conn represents a protocol connection
type Conn struct {
	net.Conn
	Protocol
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
	decoded, err := c.Decode(buf[:n])
	if err != nil {
		return 0, nil
	}
	n = copy(b, decoded)
	if len(decoded) > len(b) {
		c.buf = decoded
		c.offset = n
	}
	return n, nil
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
