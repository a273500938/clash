package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/ssr/encryption"
	"github.com/Dreamacro/clash/component/ssr/obfs"
	"github.com/Dreamacro/clash/component/ssr/protocol"
	C "github.com/Dreamacro/clash/constant"
)

type ShadowSocksR struct {
	*Base
	cipher   *encryption.SSRStreamCipher
	obfs     obfs.Obfs
	protocol protocol.Protocol
}

type ShadowSocksROption struct {
	Name          string `proxy:"name"`
	Server        string `proxy:"server"`
	Port          int    `proxy:"port"`
	Password      string `proxy:"password"`
	Cipher        string `proxy:"cipher"`
	Obfs          string `proxy:"obfs"`
	ObfsParam     string `proxy:"obfs-param,omitempty"`
	Protocol      string `proxy:"protocol"`
	ProtocolParam string `proxy:"protocol-param,omitempty"`
}

func (ssr *ShadowSocksR) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	c = obfs.StreamConn(c, ssr.obfs)
	c = ssr.cipher.StreamConn(c)
	conn, ok := c.(*encryption.Conn)
	if !ok {
		return nil, fmt.Errorf("invalid connection type")
	}
	c = protocol.StreamConn(c, ssr.protocol, conn.IV())
	_, err := c.Write(serializesSocksAddr(metadata))
	return c, err
}

func (ssr *ShadowSocksR) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	c, err := dialer.DialContext(ctx, "tcp", ssr.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", ssr.addr, err)
	}
	tcpKeepAlive(c)

	c, err = ssr.StreamConn(c, metadata)
	return NewConn(c, ssr), err
}

func (ssr *ShadowSocksR) DialUDP(metadata *C.Metadata) (C.PacketConn, error) {
	return nil, errors.New("UDP for SSR is not supported now")
}

func (ssr *ShadowSocksR) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"type": ssr.Type().String(),
	})
}

func NewShadowSocksR(option ShadowSocksROption) (*ShadowSocksR, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	cipher := option.Cipher
	password := option.Password
	coreCiph, err := encryption.PickCipher(cipher, nil, password)
	if err != nil {
		return nil, fmt.Errorf("ssr %s initialize cipher error: %w", addr, err)
	}
	ciph, ok := coreCiph.(*encryption.SSRStreamCipher)
	if !ok {
		return nil, fmt.Errorf("%s is not a supported stream cipher in ssr", cipher)
	}

	obfs, err := obfs.PickObfs(option.Obfs, &obfs.Base{
		IVSize:  ciph.IVSize(),
		Key:     ciph.Key(),
		HeadLen: 30,
		Host:    option.Server,
		Port:    option.Port,
		Param:   option.ObfsParam,
	})
	if err != nil {
		return nil, fmt.Errorf("ssr %s initialize obfs error: %w", addr, err)
	}

	protocol, err := protocol.PickProtocol(option.Protocol, &protocol.Base{
		IV:     nil,
		Key:    ciph.Key(),
		TCPMss: 1460,
		Param:  option.ProtocolParam,
	})
	if err != nil {
		return nil, fmt.Errorf("ssr %s initialize protocol error: %w", addr, err)
	}

	return &ShadowSocksR{
		Base: &Base{
			name: option.Name,
			addr: addr,
			tp:   C.ShadowsocksR,
			udp:  false,
		},
		cipher:   ciph,
		obfs:     obfs,
		protocol: protocol,
	}, nil
}
