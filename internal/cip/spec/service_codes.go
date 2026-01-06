package spec

import "github.com/tturner/cipdip/internal/cip/protocol"

// CIP service codes (authoritative registry).
const (
	CIPServiceGetAttributeAll      protocol.CIPServiceCode = 0x01
	CIPServiceSetAttributeAll      protocol.CIPServiceCode = 0x02
	CIPServiceGetAttributeList     protocol.CIPServiceCode = 0x03
	CIPServiceSetAttributeList     protocol.CIPServiceCode = 0x04
	CIPServiceReset                protocol.CIPServiceCode = 0x05
	CIPServiceStart                protocol.CIPServiceCode = 0x06
	CIPServiceStop                 protocol.CIPServiceCode = 0x07
	CIPServiceCreate               protocol.CIPServiceCode = 0x08
	CIPServiceDelete               protocol.CIPServiceCode = 0x09
	CIPServiceMultipleService      protocol.CIPServiceCode = 0x0A
	CIPServiceApplyAttributes      protocol.CIPServiceCode = 0x0D
	CIPServiceGetAttributeSingle   protocol.CIPServiceCode = 0x0E
	CIPServiceSetAttributeSingle   protocol.CIPServiceCode = 0x10
	CIPServiceFindNextObjectInst   protocol.CIPServiceCode = 0x11
	CIPServiceErrorResponse        protocol.CIPServiceCode = 0x14
	CIPServiceRestore              protocol.CIPServiceCode = 0x15
	CIPServiceSave                 protocol.CIPServiceCode = 0x16
	CIPServiceNoOp                 protocol.CIPServiceCode = 0x17
	CIPServiceGetMember            protocol.CIPServiceCode = 0x18
	CIPServiceSetMember            protocol.CIPServiceCode = 0x19
	CIPServiceInsertMember         protocol.CIPServiceCode = 0x1A
	CIPServiceRemoveMember         protocol.CIPServiceCode = 0x1B
	CIPServiceGroupSync            protocol.CIPServiceCode = 0x1C
	CIPServiceExecutePCCC          protocol.CIPServiceCode = 0x4B
	CIPServiceReadTag              protocol.CIPServiceCode = 0x4C
	CIPServiceWriteTag             protocol.CIPServiceCode = 0x4D
	CIPServiceReadModifyWrite      protocol.CIPServiceCode = 0x4E
	CIPServiceUploadTransfer       protocol.CIPServiceCode = 0x4F
	CIPServiceDownloadTransfer     protocol.CIPServiceCode = 0x50
	CIPServiceClearFile            protocol.CIPServiceCode = 0x51
	CIPServiceReadTagFragmented    protocol.CIPServiceCode = 0x52
	CIPServiceWriteTagFragmented   protocol.CIPServiceCode = 0x53
	CIPServiceForwardOpen          protocol.CIPServiceCode = 0x54
	CIPServiceGetInstanceAttrList  protocol.CIPServiceCode = 0x55
	CIPServiceGetConnectionData    protocol.CIPServiceCode = 0x56
	CIPServiceSearchConnectionData protocol.CIPServiceCode = 0x57
	CIPServiceGetConnectionOwner   protocol.CIPServiceCode = 0x5A
	CIPServiceLargeForwardOpen     protocol.CIPServiceCode = 0x5B
	CIPServiceUnconnectedSend      protocol.CIPServiceCode = 0x52
	CIPServiceForwardClose         protocol.CIPServiceCode = 0x4E
)

// File Object service aliases (share values with existing service codes).
const (
	CIPServiceInitiateUpload       protocol.CIPServiceCode = CIPServiceExecutePCCC
	CIPServiceInitiateDownload     protocol.CIPServiceCode = CIPServiceReadTag
	CIPServiceInitiatePartialRead  protocol.CIPServiceCode = CIPServiceWriteTag
	CIPServiceInitiatePartialWrite protocol.CIPServiceCode = CIPServiceReadModifyWrite
)
