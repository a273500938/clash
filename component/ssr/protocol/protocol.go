package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

var (
	errAuthAES128HMACError         = errors.New("auth_aes128_* post decrypt hmac error")
	errAuthAES128DataLengthError   = errors.New("auth_aes128_* post decrypt length mismatch")
	errAuthSHA1v4CRC32Error        = errors.New("auth_sha1_v4 post decrypt data crc32 error")
	errAuthSHA1v4DataLengthError   = errors.New("auth_sha1_v4 post decrypt data length error")
	errAuthSHA1v4IncorrectChecksum = errors.New("auth_sha1_v4 post decrypt incorrect checksum")
	errAuthChainDataLengthError    = errors.New("auth_chain_* post decrypt length mismatch")
	errAuthChainHMACError          = errors.New("auth_chain_* post decrypt hmac error")
)

type authData struct {
	clientID     []byte
	connectionID uint32
}

type recvInfo struct {
	recvID uint32
	buffer *bytes.Buffer
}

type hmacMethod func(key []byte, data []byte) []byte
type hashDigestMethod func(data []byte) []byte
type rndMethod func(dataSize int, random *shift128PlusContext, lastHash []byte, dataSizeList, dataSizeList2 []int, overhead int) int

// Protocol provides methods for decoding, encoding and iv setting
type Protocol interface {
	initForConn(iv []byte) Protocol
	SetIV(iv []byte)
	Decode([]byte) ([]byte, error)
	Encode([]byte) ([]byte, error)
}

type protocolCreator func(b *Base) Protocol

var protocolList = make(map[string]protocolCreator)

func register(name string, c protocolCreator) {
	protocolList[name] = c
}

// PickProtocol returns a protocol of the given name
func PickProtocol(name string, b *Base) (Protocol, error) {
	if protocolCreator, ok := protocolList[strings.ToLower(name)]; ok {
		return protocolCreator(b), nil
	}
	return nil, fmt.Errorf("Protocol %s not supported", name)
}
