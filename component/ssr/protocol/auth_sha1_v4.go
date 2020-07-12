package protocol

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"time"

	"github.com/Dreamacro/clash/component/ssr/tools"
)

type authSHA1V4 struct {
	*Base
	*authData
	headerSent bool
	buffer     bytes.Buffer
}

func init() {
	register("auth_sha1_v4", newAuthSHA1V4)
}

func newAuthSHA1V4(b *Base) Protocol {
	return &authSHA1V4{Base: b, authData: &authData{}}
}

func (a *authSHA1V4) initForConn(iv []byte) Protocol {
	return &authSHA1V4{
		Base: &Base{
			IV:     iv,
			Key:    a.Key,
			TCPMss: a.TCPMss,
			Param:  a.Param,
		},
		authData: a.authData,
	}
}

func (a *authSHA1V4) SetIV(iv []byte) {
	a.IV = iv
}

func (a *authSHA1V4) Decode(b []byte) ([]byte, error) {
	a.buffer.Reset()
	bSize := len(b)
	for bSize > 4 {
		crc32 := tools.CalcCRC32(b, 2, 0xFFFFFFFF)
		if binary.LittleEndian.Uint16(b[2:4]) != uint16(crc32&0xFFFF) {
			return nil, errAuthSHA1v4CRC32Error
		}
		length := int(binary.BigEndian.Uint16(b[0:2]))
		if length >= 8192 || length < 8 {
			return nil, errAuthSHA1v4DataLengthError
		}
		if length > bSize {
			break
		}

		if tools.CheckAdler32(b, length) {
			pos := int(b[4])
			if pos != 0xFF {
				pos += 4
			} else {
				pos = int(binary.BigEndian.Uint16(b[5:5+2])) + 4
			}
			retSize := length - pos - 4
			a.buffer.Write(b[pos : pos+retSize])
			bSize -= length
			b = b[length:]
		} else {
			return nil, errAuthSHA1v4IncorrectChecksum
		}
	}
	return a.buffer.Bytes(), nil
}

func (a *authSHA1V4) Encode(b []byte) ([]byte, error) {
	a.buffer.Reset()
	bSize := len(b)
	offset := 0
	if !a.headerSent && bSize > 0 {
		headSize := getHeadSize(b, 30)
		if headSize > bSize {
			headSize = bSize
		}
		a.buffer.Write(a.packAuthData(b[:headSize]))
		offset += headSize
		bSize -= headSize
		a.headerSent = true
	}
	const blockSize = 4096
	for bSize > blockSize {
		a.buffer.Write(a.packData(b[offset : offset+blockSize]))
		offset += blockSize
		bSize -= blockSize
	}
	if bSize > 0 {
		a.buffer.Write(a.packData(b[offset:]))
	}
	return a.buffer.Bytes(), nil
}

func (a *authSHA1V4) packData(data []byte) (ret []byte) {
	dataSize := len(data)
	randSize := 1

	if dataSize <= 1300 {
		if dataSize > 400 {
			randSize += rand.Intn(128)
		} else {
			randSize += rand.Intn(1024)
		}
	}

	retSize := randSize + dataSize + 8
	ret = make([]byte, retSize)
	// 0~1, ret size
	binary.BigEndian.PutUint16(ret[0:2], uint16(retSize&0xFFFF))
	// 2~3, crc of ret size
	crc32 := tools.CalcCRC32(ret, 2, 0xFFFFFFFF)
	binary.LittleEndian.PutUint16(ret[2:4], uint16(crc32&0xFFFF))
	// 4, rand size
	if randSize < 128 {
		ret[4] = uint8(randSize & 0xFF)
	} else {
		ret[4] = uint8(0xFF)
		binary.BigEndian.PutUint16(ret[5:7], uint16(randSize&0xFFFF))
	}
	// (rand size+4)~(ret size-4), data
	if dataSize > 0 {
		copy(ret[randSize+4:], data)
	}
	// (ret size-4)~end, adler32 of full data
	adler := tools.CalcAdler32(ret[:retSize-4])
	binary.LittleEndian.PutUint32(ret[retSize-4:], adler)

	return ret
}

func (a *authSHA1V4) packAuthData(data []byte) (ret []byte) {
	dataSize := len(data)
	randSize := 1
	if dataSize <= 1300 {
		if dataSize > 400 {
			randSize += rand.Intn(128)
		} else {
			randSize += rand.Intn(1024)
		}
	}
	dataOffset := randSize + 4 + 2
	retSize := dataOffset + dataSize + 12 + tools.HmacSHA1Len
	ret = make([]byte, retSize)
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.connectionID++
	if a.connectionID > 0xFF000000 {
		a.clientID = nil
	}
	if len(a.clientID) == 0 {
		a.clientID = make([]byte, 8)
		rand.Read(a.clientID)
		b := make([]byte, 4)
		rand.Read(b)
		a.connectionID = binary.LittleEndian.Uint32(b) & 0xFFFFFF
	}
	// 0~1, ret size
	binary.BigEndian.PutUint16(ret[0:2], uint16(retSize&0xFFFF))

	// 2~6, crc of (ret size+salt+key)
	salt := []byte("auth_sha1_v4")
	crcData := make([]byte, len(salt)+len(a.Key)+2)
	copy(crcData[0:2], ret[0:2])
	copy(crcData[2:], salt)
	copy(crcData[2+len(salt):], a.Key)
	crc32 := tools.CalcCRC32(crcData, len(crcData), 0xFFFFFFFF)
	// 2~6, crc of (ret size+salt+key)
	binary.LittleEndian.PutUint32(ret[2:], crc32)
	// 6~(rand size+6), rand numbers
	rand.Read(ret[dataOffset-randSize : dataOffset])
	// 6, rand size
	if randSize < 128 {
		ret[6] = byte(randSize & 0xFF)
	} else {
		// 6, magic number 0xFF
		ret[6] = 0xFF
		// 7~8, rand size
		binary.BigEndian.PutUint16(ret[7:9], uint16(randSize&0xFFFF))
	}
	// rand size+6~(rand size+10), time stamp
	now := time.Now().Unix()
	binary.LittleEndian.PutUint32(ret[dataOffset:dataOffset+4], uint32(now))
	// rand size+10~(rand size+14), client ID
	copy(ret[dataOffset+4:dataOffset+4+4], a.clientID[0:4])
	// rand size+14~(rand size+18), connection ID
	binary.LittleEndian.PutUint32(ret[dataOffset+8:dataOffset+8+4], a.connectionID)
	// rand size+18~(rand size+18)+data length, data
	copy(ret[dataOffset+12:], data)

	key := make([]byte, len(a.IV)+len(a.Key))
	copy(key, a.IV)
	copy(key[len(a.IV):], a.Key)

	h := tools.HmacSHA1(key, ret[:retSize-tools.HmacSHA1Len])
	// (ret size-10)~(ret size)/(rand size)+18+data length~end, hmac
	copy(ret[retSize-tools.HmacSHA1Len:], h[0:tools.HmacSHA1Len])
	return ret
}

func getHeadSize(data []byte, defaultValue int) int {
	if data == nil || len(data) < 2 {
		return defaultValue
	}
	headType := data[0] & 0x07
	switch headType {
	case 1:
		// IPv4 1+4+2
		return 7
	case 4:
		// IPv6 1+16+2
		return 19
	case 3:
		// domain name, variant length
		return 4 + int(data[1])
	}

	return defaultValue
}
