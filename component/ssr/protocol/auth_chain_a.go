package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rc4"
	"encoding/base64"
	"encoding/binary"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Dreamacro/clash/component/ssr/encryption"
	"github.com/Dreamacro/clash/component/ssr/tools"
)

type authChain struct {
	*Base
	*recvInfo
	*authData
	randomClient   shift128PlusContext
	randomServer   shift128PlusContext
	enc            cipher.Stream
	dec            cipher.Stream
	headerSent     bool
	lastClientHash []byte
	lastServerHash []byte
	userKey        []byte
	uid            [4]byte
	salt           string
	hmac           hmacMethod
	hashDigest     hashDigestMethod
	rnd            rndMethod
	dataSizeList   []int
	dataSizeList2  []int
	chunkID        uint32
}

func init() {
	register("auth_chain_a", newAuthChainA)
}

func newAuthChainA(b *Base) Protocol {
	return &authChain{
		Base:       b,
		authData:   &authData{},
		salt:       "auth_chain_a",
		hmac:       tools.HmacMD5,
		hashDigest: tools.SHA1Sum,
		rnd:        authChainAGetRandLen,
	}
}

func (a *authChain) initForConn(iv []byte) Protocol {
	r := &authChain{
		Base: &Base{
			IV:     iv,
			Key:    a.Key,
			TCPMss: a.TCPMss,
			Param:  a.Param,
		},
		recvInfo:   &recvInfo{recvID: 1, buffer: new(bytes.Buffer)},
		authData:   a.authData,
		salt:       a.salt,
		hmac:       a.hmac,
		hashDigest: a.hashDigest,
		rnd:        a.rnd,
	}
	if a.salt == "auth_chain_b" {
		random := a.randomServer
		// random := &shift128PlusContext{}
		random.InitFromBin(a.Key)
		len := random.Next()%8 + 4
		for i := 0; i < int(len); i++ {
			a.dataSizeList = append(a.dataSizeList, (int)(random.Next()%2340%2040%1440))
		}
		sort.Ints(a.dataSizeList)

		len = random.Next()%16 + 8
		for i := 0; i < int(len); i++ {
			a.dataSizeList2 = append(a.dataSizeList2, (int)(random.Next()%2340%2040%1440))
		}
		sort.Ints(a.dataSizeList2)
	}
	return r
}

func (a *authChain) SetIV(iv []byte) {
	a.IV = iv
}

func (a *authChain) Decode(b []byte) ([]byte, error) {
	a.buffer.Reset()
	key := make([]byte, len(a.userKey)+4)
	copy(key, a.userKey)
	for len(b) > 4 {
		binary.LittleEndian.PutUint32(key[len(a.userKey):], a.recvID)
		dataLen := (int)((uint(b[1]^a.lastServerHash[15]) << 8) + uint(b[0]^a.lastServerHash[14]))
		randLen := a.getServerRandLen(dataLen, 4)
		length := randLen + dataLen
		if length >= 4096 {
			return nil, errAuthChainDataLengthError
		}
		length += 4
		if length > len(b) {
			break
		}

		hash := a.hmac(key, b[:length-2])
		if !bytes.Equal(hash[:2], b[length-2:length]) {
			return nil, errAuthChainHMACError
		}
		var dataPos int
		if dataLen > 0 && randLen > 0 {
			dataPos = 2 + getRandStartPos(&a.randomServer, randLen)
		} else {
			dataPos = 2
		}
		d := make([]byte, dataLen)
		a.dec.XORKeyStream(d, b[dataPos:dataPos+dataLen])
		a.buffer.Write(d)
		if a.recvID == 1 {
			a.TCPMss = int(binary.LittleEndian.Uint16(a.buffer.Next(2)))
		}
		a.lastServerHash = hash
		a.recvID++
		b = b[length:]
	}
	return a.buffer.Bytes(), nil
}

func (a *authChain) Encode(b []byte) ([]byte, error) {
	a.buffer.Reset()
	bSize := len(b)
	offset := 0
	if bSize > 0 && !a.headerSent {
		headSize := 1200
		if headSize > bSize {
			headSize = bSize
		}
		a.buffer.Write(a.packAuthData(b[:headSize]))
		offset += headSize
		bSize -= headSize
		a.headerSent = true
	}
	var unitSize = a.TCPMss - 4
	for bSize > unitSize {
		dataLen, randLength := a.packedDataLen(b[offset : offset+unitSize])
		d := make([]byte, dataLen)
		a.packData(d, b[offset:offset+unitSize], randLength)
		a.buffer.Write(d)
		bSize -= unitSize
		offset += unitSize
	}
	if bSize > 0 {
		dataLen, randLength := a.packedDataLen(b[offset:])
		d := make([]byte, dataLen)
		a.packData(d, b[offset:], randLength)
		a.buffer.Write(d)
	}
	return a.buffer.Bytes(), nil
}

func (a *authChain) getClientRandLen(dataLength int, overhead int) int {
	return a.rnd(dataLength, &a.randomClient, a.lastClientHash, a.dataSizeList, a.dataSizeList2, overhead)
}

func (a *authChain) getServerRandLen(dataLength int, overhead int) int {
	return a.rnd(dataLength, &a.randomServer, a.lastServerHash, a.dataSizeList, a.dataSizeList2, overhead)
}

func (a *authChain) packedDataLen(data []byte) (chunkLength, randLength int) {
	dataLength := len(data)
	randLength = a.getClientRandLen(dataLength, 4)
	chunkLength = randLength + dataLength + 2 + 2
	return
}

func (a *authChain) packData(outData []byte, data []byte, randLength int) {
	dataLength := len(data)
	outLength := randLength + dataLength + 2
	outData[0] = byte(dataLength) ^ a.lastClientHash[14]
	outData[1] = byte(dataLength>>8) ^ a.lastClientHash[15]

	{
		if dataLength > 0 {
			randPart1Length := getRandStartPos(&a.randomClient, randLength)
			rand.Read(outData[2 : 2+randPart1Length])
			a.enc.XORKeyStream(outData[2+randPart1Length:], data)
			rand.Read(outData[2+randPart1Length+dataLength : outLength])
		} else {
			rand.Read(outData[2 : 2+randLength])
		}
	}

	userKeyLen := uint8(len(a.userKey))
	key := make([]byte, userKeyLen+4)
	copy(key, a.userKey)
	a.chunkID++
	binary.LittleEndian.PutUint32(key[userKeyLen:], a.chunkID)
	a.lastClientHash = a.hmac(key, outData[:outLength])
	copy(outData[outLength:], a.lastClientHash[:2])
	return
}

const authHeadLength = 4 + 8 + 4 + 16 + 4

func (a *authChain) packAuthData(data []byte) (outData []byte) {
	outData = make([]byte, authHeadLength, authHeadLength+1500)
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.connectionID++
	if a.connectionID > 0xFF000000 {
		rand.Read(a.clientID)
		b := make([]byte, 4)
		rand.Read(b)
		a.connectionID = binary.LittleEndian.Uint32(b) & 0xFFFFFF
	}
	var key = make([]byte, len(a.IV)+len(a.Key))
	copy(key, a.IV)
	copy(key[len(a.IV):], a.Key)

	encrypt := make([]byte, 20)
	t := time.Now().Unix()
	binary.LittleEndian.PutUint32(encrypt[:4], uint32(t))
	copy(encrypt[4:8], a.clientID)
	binary.LittleEndian.PutUint32(encrypt[8:], a.connectionID)
	binary.LittleEndian.PutUint16(encrypt[12:], 4)
	binary.LittleEndian.PutUint16(encrypt[14:], 0)

	// first 12 bytes
	{
		rand.Read(outData[:4])
		a.lastClientHash = a.hmac(key, outData[:4])
		copy(outData[4:], a.lastClientHash[:8])
	}
	var base64UserKey string
	// uid & 16 bytes auth data
	{
		uid := make([]byte, 4)
		if a.userKey == nil {
			params := strings.Split(a.Param, ":")
			if len(params) >= 2 {
				if userID, err := strconv.ParseUint(params[0], 10, 32); err == nil {
					binary.LittleEndian.PutUint32(a.uid[:], uint32(userID))
					a.userKey = a.hashDigest([]byte(params[1]))
				}
			}
			if a.userKey == nil {
				rand.Read(a.uid[:])
				a.userKey = make([]byte, len(a.Key))
				copy(a.userKey, a.Key)
			}
		}
		for i := 0; i < 4; i++ {
			uid[i] = a.uid[i] ^ a.lastClientHash[8+i]
		}
		base64UserKey = base64.StdEncoding.EncodeToString(a.userKey)
		aesCipherKey := encryption.Kdf(base64UserKey+a.salt, 16)
		block, err := aes.NewCipher(aesCipherKey)
		if err != nil {
			return
		}
		encryptData := make([]byte, 16)
		iv := make([]byte, aes.BlockSize)
		cbc := cipher.NewCBCEncrypter(block, iv)
		cbc.CryptBlocks(encryptData, encrypt[:16])
		copy(encrypt[:4], uid[:])
		copy(encrypt[4:4+16], encryptData)
	}
	// final HMAC
	{
		a.lastServerHash = a.hmac(a.userKey, encrypt[0:20])

		copy(outData[12:], encrypt)
		copy(outData[12+20:], a.lastServerHash[:4])
	}

	// init cipher
	password := make([]byte, len(base64UserKey)+base64.StdEncoding.EncodedLen(16))
	copy(password, base64UserKey)
	base64.StdEncoding.Encode(password[len(base64UserKey):], a.lastClientHash[:16])

	cipherKey := encryption.Kdf(string(password), 16)
	a.enc, _ = rc4.NewCipher(cipherKey)
	a.dec, _ = rc4.NewCipher(cipherKey)

	// data
	chunkLength, randLength := a.packedDataLen(data)
	if chunkLength <= 1500 {
		outData = outData[:authHeadLength+chunkLength]
	} else {
		newOutData := make([]byte, authHeadLength+chunkLength)
		copy(newOutData, outData[:authHeadLength])
		outData = newOutData
	}
	a.packData(outData[authHeadLength:], data, randLength)
	return
}

func getRandStartPos(random *shift128PlusContext, randLength int) int {
	if randLength > 0 {
		return int(random.Next() % 8589934609 % uint64(randLength))
	}
	return 0
}

func authChainAGetRandLen(dataLength int, random *shift128PlusContext, lastHash []byte, dataSizeList, dataSizeList2 []int, overhead int) int {
	if dataLength > 1440 {
		return 0
	}
	random.InitFromBinDatalen(lastHash[:16], dataLength)
	if dataLength > 1300 {
		return int(random.Next() % 31)
	}
	if dataLength > 900 {
		return int(random.Next() % 127)
	}
	if dataLength > 400 {
		return int(random.Next() % 521)
	}
	return int(random.Next() % 1021)
}

type shift128PlusContext struct {
	v [2]uint64
}

func (ctx *shift128PlusContext) InitFromBin(bin []byte) {
	var fillBin [16]byte
	copy(fillBin[:], bin)

	ctx.v[0] = binary.LittleEndian.Uint64(fillBin[:8])
	ctx.v[1] = binary.LittleEndian.Uint64(fillBin[8:])
}

func (ctx *shift128PlusContext) InitFromBinDatalen(bin []byte, datalen int) {
	var fillBin [16]byte
	copy(fillBin[:], bin)
	binary.LittleEndian.PutUint16(fillBin[:2], uint16(datalen))

	ctx.v[0] = binary.LittleEndian.Uint64(fillBin[:8])
	ctx.v[1] = binary.LittleEndian.Uint64(fillBin[8:])

	for i := 0; i < 4; i++ {
		ctx.Next()
	}
}

func (ctx *shift128PlusContext) Next() uint64 {
	x := ctx.v[0]
	y := ctx.v[1]
	ctx.v[0] = y
	x ^= x << 23
	x ^= y ^ (x >> 17) ^ (y >> 26)
	ctx.v[1] = x
	return x + y
}
