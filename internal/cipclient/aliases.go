package cipclient

import (
	"fmt"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"strings"
)

var cipServiceAliases = map[string]uint8{
	"get_attributes_all":          uint8(protocol.CIPServiceGetAttributeAll),
	"get_attribute_all":           uint8(protocol.CIPServiceGetAttributeAll),
	"set_attributes_all":          uint8(protocol.CIPServiceSetAttributeAll),
	"set_attribute_all":           uint8(protocol.CIPServiceSetAttributeAll),
	"get_attribute_list":          uint8(protocol.CIPServiceGetAttributeList),
	"set_attribute_list":          uint8(protocol.CIPServiceSetAttributeList),
	"reset":                       uint8(protocol.CIPServiceReset),
	"start":                       uint8(protocol.CIPServiceStart),
	"stop":                        uint8(protocol.CIPServiceStop),
	"create":                      uint8(protocol.CIPServiceCreate),
	"delete":                      uint8(protocol.CIPServiceDelete),
	"multiple_service_request":    uint8(protocol.CIPServiceMultipleService),
	"multiple_service_packet":     uint8(protocol.CIPServiceMultipleService),
	"multiple_service":            uint8(protocol.CIPServiceMultipleService),
	"apply_attributes":            uint8(protocol.CIPServiceApplyAttributes),
	"get_attribute_single":        uint8(protocol.CIPServiceGetAttributeSingle),
	"set_attribute_single":        uint8(protocol.CIPServiceSetAttributeSingle),
	"find_next_object_instance":   uint8(protocol.CIPServiceFindNextObjectInst),
	"error_response":              uint8(protocol.CIPServiceErrorResponse),
	"restore":                     uint8(protocol.CIPServiceRestore),
	"save":                        uint8(protocol.CIPServiceSave),
	"nop":                         uint8(protocol.CIPServiceNoOp),
	"get_member":                  uint8(protocol.CIPServiceGetMember),
	"set_member":                  uint8(protocol.CIPServiceSetMember),
	"insert_member":               uint8(protocol.CIPServiceInsertMember),
	"remove_member":               uint8(protocol.CIPServiceRemoveMember),
	"group_sync":                  uint8(protocol.CIPServiceGroupSync),
	"execute_pccc":                uint8(protocol.CIPServiceExecutePCCC),
	"read_tag":                    uint8(protocol.CIPServiceReadTag),
	"write_tag":                   uint8(protocol.CIPServiceWriteTag),
	"read_modify_write":           uint8(protocol.CIPServiceReadModifyWrite),
	"forward_close":               uint8(protocol.CIPServiceForwardClose),
	"upload_transfer":             uint8(protocol.CIPServiceUploadTransfer),
	"download_transfer":           uint8(protocol.CIPServiceDownloadTransfer),
	"clear_file":                  uint8(protocol.CIPServiceClearFile),
	"read_tag_fragmented":         uint8(protocol.CIPServiceReadTagFragmented),
	"write_tag_fragmented":        uint8(protocol.CIPServiceWriteTagFragmented),
	"get_instance_attribute_list": uint8(protocol.CIPServiceGetInstanceAttrList),
	"unconnected_send":            uint8(protocol.CIPServiceUnconnectedSend),
	"get_connection_data":         uint8(protocol.CIPServiceGetConnectionData),
	"search_connection_data":      uint8(protocol.CIPServiceSearchConnectionData),
	"get_connection_owner":        uint8(protocol.CIPServiceGetConnectionOwner),
	"large_forward_open":          uint8(protocol.CIPServiceLargeForwardOpen),
	"forward_open":                uint8(protocol.CIPServiceForwardOpen),
	"initiate_upload":             uint8(protocol.CIPServiceInitiateUpload),
	"initiate_download":           uint8(protocol.CIPServiceInitiateDownload),
	"initiate_partial_read":       uint8(protocol.CIPServiceInitiatePartialRead),
	"initiate_partial_write":      uint8(protocol.CIPServiceInitiatePartialWrite),
}

var cipServiceAliasNames = map[uint8]string{
	uint8(protocol.CIPServiceGetAttributeAll):      "get_attributes_all",
	uint8(protocol.CIPServiceSetAttributeAll):      "set_attributes_all",
	uint8(protocol.CIPServiceGetAttributeList):     "get_attribute_list",
	uint8(protocol.CIPServiceSetAttributeList):     "set_attribute_list",
	uint8(protocol.CIPServiceReset):                "reset",
	uint8(protocol.CIPServiceStart):                "start",
	uint8(protocol.CIPServiceStop):                 "stop",
	uint8(protocol.CIPServiceCreate):               "create",
	uint8(protocol.CIPServiceDelete):               "delete",
	uint8(protocol.CIPServiceMultipleService):      "multiple_service_request",
	uint8(protocol.CIPServiceApplyAttributes):      "apply_attributes",
	uint8(protocol.CIPServiceGetAttributeSingle):   "get_attribute_single",
	uint8(protocol.CIPServiceSetAttributeSingle):   "set_attribute_single",
	uint8(protocol.CIPServiceFindNextObjectInst):   "find_next_object_instance",
	uint8(protocol.CIPServiceErrorResponse):        "error_response",
	uint8(protocol.CIPServiceRestore):              "restore",
	uint8(protocol.CIPServiceSave):                 "save",
	uint8(protocol.CIPServiceNoOp):                 "nop",
	uint8(protocol.CIPServiceGetMember):            "get_member",
	uint8(protocol.CIPServiceSetMember):            "set_member",
	uint8(protocol.CIPServiceInsertMember):         "insert_member",
	uint8(protocol.CIPServiceRemoveMember):         "remove_member",
	uint8(protocol.CIPServiceGroupSync):            "group_sync",
	uint8(protocol.CIPServiceExecutePCCC):          "execute_pccc",
	uint8(protocol.CIPServiceReadTag):              "read_tag",
	uint8(protocol.CIPServiceWriteTag):             "write_tag",
	uint8(protocol.CIPServiceForwardClose):         "forward_close",
	uint8(protocol.CIPServiceUploadTransfer):       "upload_transfer",
	uint8(protocol.CIPServiceDownloadTransfer):     "download_transfer",
	uint8(protocol.CIPServiceClearFile):            "clear_file",
	uint8(protocol.CIPServiceReadTagFragmented):    "unconnected_send",
	uint8(protocol.CIPServiceWriteTagFragmented):   "write_tag_fragmented",
	uint8(protocol.CIPServiceGetInstanceAttrList):  "get_instance_attribute_list",
	uint8(protocol.CIPServiceGetConnectionData):    "get_connection_data",
	uint8(protocol.CIPServiceSearchConnectionData): "search_connection_data",
	uint8(protocol.CIPServiceGetConnectionOwner):   "get_connection_owner",
	uint8(protocol.CIPServiceLargeForwardOpen):     "large_forward_open",
	uint8(protocol.CIPServiceForwardOpen):          "forward_open",
}

var cipClassAliases = map[string]uint16{
	"identity_object":    0x01,
	"message_router":     0x02,
	"assembly":           0x04,
	"connection":         0x05,
	"connection_manager": 0x06,
	"file_object":        0x37,
	"event_log":          0x41,
	"motion_axis":        0x42,
	"time_sync":          0x43,
	"modbus":             0x44,
	"symbol_object":      0x6B,
	"template_object":    0x6C,
	"program_name":       0x64,
	"pccc_object":        0x67,
	"safety_supervisor":  0x39,
	"safety_validator":   0x3A,
	"tcp_ip_interface":   0xF5,
	"ethernet_link":      0xF6,
}

var cipClassAliasNames = map[uint16]string{
	0x01: "identity_object",
	0x02: "message_router",
	0x04: "assembly",
	0x05: "connection",
	0x06: "connection_manager",
	0x37: "file_object",
	0x41: "event_log",
	0x42: "motion_axis",
	0x43: "time_sync",
	0x44: "modbus",
	0x6B: "symbol_object",
	0x6C: "template_object",
	0x64: "program_name",
	0x67: "pccc_object",
	0x39: "safety_supervisor",
	0x3A: "safety_validator",
	0xF5: "tcp_ip_interface",
	0xF6: "ethernet_link",
}

func NormalizeAlias(input string) string {
	clean := strings.ToLower(strings.TrimSpace(input))
	clean = strings.ReplaceAll(clean, "-", "_")
	clean = strings.ReplaceAll(clean, " ", "_")
	for strings.Contains(clean, "__") {
		clean = strings.ReplaceAll(clean, "__", "_")
	}
	return clean
}

func ParseServiceAlias(input string) (uint8, bool) {
	alias := NormalizeAlias(input)
	code, ok := cipServiceAliases[alias]
	return code, ok
}

func ParseClassAlias(input string) (uint16, bool) {
	alias := NormalizeAlias(input)
	code, ok := cipClassAliases[alias]
	return code, ok
}

func ServiceAliasName(code uint8) (string, bool) {
	name, ok := cipServiceAliasNames[code]
	return name, ok
}

func ClassAliasName(code uint16) (string, bool) {
	name, ok := cipClassAliasNames[code]
	return name, ok
}

func FormatServiceAlias(code uint8) string {
	if name, ok := ServiceAliasName(code); ok {
		return name
	}
	return fmt.Sprintf("0x%02X", code)
}

func FormatClassAlias(code uint16) string {
	if name, ok := ClassAliasName(code); ok {
		return name
	}
	return fmt.Sprintf("0x%04X", code)
}
