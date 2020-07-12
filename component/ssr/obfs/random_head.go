package obfs

import (
	"math/rand"

	"github.com/Dreamacro/clash/component/ssr/tools"
)

type randomHead struct {
	*Base
	firstRequest  bool
	firstResponse bool
	headerSent    bool
	buffer        []byte
}

func init() {
	register("random_head", newRandomHead)
}

func newRandomHead(b *Base) Obfs {
	return &randomHead{Base: b}
}

func (r *randomHead) initForConn() Obfs {
	return &randomHead{
		Base:          r.Base,
		firstRequest:  true,
		firstResponse: true,
	}
}

func (r *randomHead) Encode(b []byte) (encoded []byte, err error) {
	if !r.firstRequest {
		return b, nil
	}

	bSize := len(b)
	if r.headerSent {
		if bSize > 0 {
			d := make([]byte, len(r.buffer)+bSize)
			copy(d, r.buffer)
			copy(d[len(r.buffer):], b)
			r.buffer = d
		} else {
			encoded = r.buffer
			r.buffer = nil
			r.firstRequest = false
		}
	} else {
		size := rand.Intn(96) + 8
		encoded = make([]byte, size)
		rand.Read(encoded)
		tools.SetCRC32(encoded, size)

		d := make([]byte, bSize)
		copy(d, b)
		r.buffer = d
	}
	r.headerSent = true
	return encoded, nil
}

func (r *randomHead) Decode(b []byte) ([]byte, bool, error) {
	if r.firstResponse {
		r.firstResponse = false
		return b, true, nil
	}
	return b, false, nil
}
