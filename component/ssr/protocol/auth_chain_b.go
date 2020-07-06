package protocol

import (
	"bytes"
	"sort"

	"github.com/Dreamacro/clash/component/ssr/tools"
)

func init() {
	register("auth_chain_b", newAuthChainB)
}

func newAuthChainB(b *Base) Protocol {
	return &authChain{
		Base:       b,
		recvInfo:   &recvInfo{buffer: new(bytes.Buffer)},
		authData:   &authData{},
		salt:       "auth_chain_b",
		hmac:       tools.HmacMD5,
		hashDigest: tools.SHA1Sum,
		rnd:        authChainBGetRandLen,
	}
}

func authChainBGetRandLen(dataLength int, random *shift128PlusContext, lastHash []byte, dataSizeList, dataSizeList2 []int, overhead int) int {
	if dataLength > 1440 {
		return 0
	}
	random.InitFromBinDatalen(lastHash[:16], dataLength)
	pos := sort.SearchInts(dataSizeList, dataLength+overhead) // lower_bound
	// pos := sort.Search(len(dataSizeList), func(i int) bool { return dataSizeList[i] > dataLength+overhead }) // upper_bound
	// pos := binarySearch(0, len(dataSizeList)-1, dataSizeList, dataLength+overhead)                           // upper_bound
	finalPos := uint64(pos) + random.Next()%uint64(len(dataSizeList))
	if finalPos < uint64(len(dataSizeList)) {
		return dataSizeList[finalPos] - dataLength - overhead
	}

	pos = sort.SearchInts(dataSizeList2, dataLength+overhead) // lower_bound
	// pos = sort.Search(len(dataSizeList2), func(i int) bool { return dataSizeList2[i] > dataLength+overhead }) // upper_bound
	// pos = binarySearch(0, len(dataSizeList2)-1, dataSizeList2, dataLength+overhead)                           // upper_bound
	finalPos = uint64(pos) + random.Next()%uint64(len(dataSizeList2))
	if finalPos < uint64(len(dataSizeList2)) {
		return dataSizeList2[finalPos] - dataLength - overhead
	}
	if finalPos < uint64(pos+len(dataSizeList2)-1) {
		return 0
	}

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

func binarySearch(start, end int, array []int, val int) int {
	mid := (start + end) / 2

	if start > end {
		if start == len(array) || val > array[start] {
			return start + 1
		}
		return start
	}

	if array[mid] > val {
		return binarySearch(start, mid-1, array, val)
	}
	return binarySearch(mid+1, end, array, val)
}
