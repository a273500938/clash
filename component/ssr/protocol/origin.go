package protocol

type origin struct{ *Base }

func init() {
	register("origin", newOrigin)
}

func newOrigin(b *Base) Protocol {
	return &origin{}
}

func (o *origin) initForConn(iv []byte) Protocol { return &origin{} }

func (o *origin) SetIV(iv []byte) {
	o.IV = iv
}

func (o *origin) Decode(b []byte) ([]byte, error) {
	return b, nil
}

func (o *origin) Encode(b []byte) ([]byte, error) {
	return b, nil
}
