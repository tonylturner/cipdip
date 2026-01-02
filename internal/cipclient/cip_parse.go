package cipclient

import (
	"encoding/binary"
	"fmt"
)

type CIPMessageInfo struct {
	Service       uint8
	BaseService   uint8
	IsResponse    bool
	PathBytes     []byte
	UsedPathSize  bool
	PathInfo      EPATHInfo
	DataOffset    int
	RequestData   []byte
	GeneralStatus *uint8
}

func parseCIPMessage(cipData []byte) (CIPMessageInfo, error) {
	if len(cipData) < 1 {
		return CIPMessageInfo{}, fmt.Errorf("CIP data too short")
	}
	info := CIPMessageInfo{}
	info.Service = cipData[0]
	info.IsResponse = info.Service&0x80 != 0
	if info.IsResponse {
		info.BaseService = info.Service & 0x7F
		status, payload, ok := parseCIPResponsePayload(cipData)
		if ok {
			info.GeneralStatus = &status
			info.RequestData = payload
		}
		return info, nil
	}

	info.BaseService = info.Service
	pathBytes, usedPathSize, dataOffset, pathInfo, err := parseCIPRequestPath(cipData)
	if err == nil {
		info.PathBytes = pathBytes
		info.UsedPathSize = usedPathSize
		info.PathInfo = pathInfo
		info.DataOffset = dataOffset
		if dataOffset <= len(cipData) {
			info.RequestData = cipData[dataOffset:]
		}
	}
	return info, nil
}

func parseCIPResponsePayload(cipData []byte) (uint8, []byte, bool) {
	if len(cipData) < 4 {
		return 0, nil, false
	}
	status := cipData[2]
	addWords := int(cipData[3])
	offset := 4 + addWords*2
	if len(cipData) < offset {
		return status, nil, false
	}
	return status, cipData[offset:], true
}

func parseCIPRequestPath(cipData []byte) ([]byte, bool, int, EPATHInfo, error) {
	if len(cipData) < 2 {
		return nil, false, 0, EPATHInfo{}, fmt.Errorf("CIP request too short")
	}
	pathSizeWords := int(cipData[1])
	pathBytesLen := pathSizeWords * 2
	if pathBytesLen > 0 && len(cipData) >= 2+pathBytesLen {
		pathBytes := make([]byte, pathBytesLen)
		copy(pathBytes, cipData[2:2+pathBytesLen])
		if looksLikeEPATH(pathBytes) {
			pathInfo, err := ParseEPATH(pathBytes)
			if err == nil {
				return pathBytes, true, 2 + pathBytesLen, pathInfo, nil
			}
		}
	}

	pathBytes := cipData[1:]
	if looksLikeEPATH(pathBytes) {
		pathInfo, err := ParseEPATH(pathBytes)
		if err == nil {
			consumed := pathInfo.BytesConsumed
			if consumed == 0 {
				consumed = len(pathBytes)
			}
			return pathBytes[:consumed], false, 1 + consumed, pathInfo, nil
		}
	}

	return nil, false, 0, EPATHInfo{}, fmt.Errorf("invalid EPATH")
}

func parseUnconnectedSendRequest(data []byte) ([]byte, bool) {
	if len(data) < 4 {
		return nil, false
	}
	msgSize := binary.LittleEndian.Uint16(data[2:4])
	offset := 4
	msgBytes := sizeToBytes(msgSize, len(data)-offset)
	if msgBytes == 0 || offset+msgBytes > len(data) {
		return nil, false
	}
	return data[offset : offset+msgBytes], true
}

func parseUnconnectedSendResponse(payload []byte) ([]byte, bool) {
	if len(payload) < 2 {
		return nil, false
	}
	msgSize := binary.LittleEndian.Uint16(payload[0:2])
	offset := 2
	msgBytes := sizeToBytes(msgSize, len(payload)-offset)
	if msgBytes == 0 || offset+msgBytes > len(payload) {
		return nil, false
	}
	return payload[offset : offset+msgBytes], true
}

func sizeToBytes(size uint16, remaining int) int {
	if int(size) <= remaining {
		return int(size)
	}
	if int(size)*2 <= remaining {
		return int(size) * 2
	}
	return 0
}
