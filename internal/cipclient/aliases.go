package cipclient

import (
	"fmt"
	"strings"
)

var cipServiceAliases = map[string]uint8{
	"get_attributes_all":          uint8(CIPServiceGetAttributeAll),
	"get_attribute_all":           uint8(CIPServiceGetAttributeAll),
	"set_attributes_all":          uint8(CIPServiceSetAttributeAll),
	"set_attribute_all":           uint8(CIPServiceSetAttributeAll),
	"get_attribute_list":          uint8(CIPServiceGetAttributeList),
	"set_attribute_list":          uint8(CIPServiceSetAttributeList),
	"reset":                       uint8(CIPServiceReset),
	"start":                       uint8(CIPServiceStart),
	"stop":                        uint8(CIPServiceStop),
	"create":                      uint8(CIPServiceCreate),
	"delete":                      uint8(CIPServiceDelete),
	"multiple_service_request":    uint8(CIPServiceMultipleService),
	"multiple_service_packet":     uint8(CIPServiceMultipleService),
	"multiple_service":            uint8(CIPServiceMultipleService),
	"apply_attributes":            uint8(CIPServiceApplyAttributes),
	"get_attribute_single":        uint8(CIPServiceGetAttributeSingle),
	"set_attribute_single":        uint8(CIPServiceSetAttributeSingle),
	"find_next_object_instance":   uint8(CIPServiceFindNextObjectInst),
	"error_response":              uint8(CIPServiceErrorResponse),
	"restore":                     uint8(CIPServiceRestore),
	"save":                        uint8(CIPServiceSave),
	"nop":                         uint8(CIPServiceNoOp),
	"get_member":                  uint8(CIPServiceGetMember),
	"set_member":                  uint8(CIPServiceSetMember),
	"insert_member":               uint8(CIPServiceInsertMember),
	"remove_member":               uint8(CIPServiceRemoveMember),
	"group_sync":                  uint8(CIPServiceGroupSync),
	"execute_pccc":                uint8(CIPServiceExecutePCCC),
	"read_tag":                    uint8(CIPServiceReadTag),
	"write_tag":                   uint8(CIPServiceWriteTag),
	"read_modify_write":           uint8(CIPServiceReadModifyWrite),
	"forward_close":               uint8(CIPServiceForwardClose),
	"upload_transfer":             uint8(CIPServiceUploadTransfer),
	"download_transfer":           uint8(CIPServiceDownloadTransfer),
	"clear_file":                  uint8(CIPServiceClearFile),
	"read_tag_fragmented":         uint8(CIPServiceReadTagFragmented),
	"write_tag_fragmented":        uint8(CIPServiceWriteTagFragmented),
	"get_instance_attribute_list": uint8(CIPServiceGetInstanceAttrList),
	"unconnected_send":            uint8(CIPServiceUnconnectedSend),
	"get_connection_data":         uint8(CIPServiceGetConnectionData),
	"search_connection_data":      uint8(CIPServiceSearchConnectionData),
	"get_connection_owner":        uint8(CIPServiceGetConnectionOwner),
	"large_forward_open":          uint8(CIPServiceLargeForwardOpen),
	"forward_open":                uint8(CIPServiceForwardOpen),
	"initiate_upload":             uint8(CIPServiceInitiateUpload),
	"initiate_download":           uint8(CIPServiceInitiateDownload),
	"initiate_partial_read":       uint8(CIPServiceInitiatePartialRead),
	"initiate_partial_write":      uint8(CIPServiceInitiatePartialWrite),
}

var cipServiceAliasNames = map[uint8]string{
	uint8(CIPServiceGetAttributeAll):      "get_attributes_all",
	uint8(CIPServiceSetAttributeAll):      "set_attributes_all",
	uint8(CIPServiceGetAttributeList):     "get_attribute_list",
	uint8(CIPServiceSetAttributeList):     "set_attribute_list",
	uint8(CIPServiceReset):                "reset",
	uint8(CIPServiceStart):                "start",
	uint8(CIPServiceStop):                 "stop",
	uint8(CIPServiceCreate):               "create",
	uint8(CIPServiceDelete):               "delete",
	uint8(CIPServiceMultipleService):      "multiple_service_request",
	uint8(CIPServiceApplyAttributes):      "apply_attributes",
	uint8(CIPServiceGetAttributeSingle):   "get_attribute_single",
	uint8(CIPServiceSetAttributeSingle):   "set_attribute_single",
	uint8(CIPServiceFindNextObjectInst):   "find_next_object_instance",
	uint8(CIPServiceErrorResponse):        "error_response",
	uint8(CIPServiceRestore):              "restore",
	uint8(CIPServiceSave):                 "save",
	uint8(CIPServiceNoOp):                 "nop",
	uint8(CIPServiceGetMember):            "get_member",
	uint8(CIPServiceSetMember):            "set_member",
	uint8(CIPServiceInsertMember):         "insert_member",
	uint8(CIPServiceRemoveMember):         "remove_member",
	uint8(CIPServiceGroupSync):            "group_sync",
	uint8(CIPServiceExecutePCCC):          "execute_pccc",
	uint8(CIPServiceReadTag):              "read_tag",
	uint8(CIPServiceWriteTag):             "write_tag",
	uint8(CIPServiceForwardClose):         "forward_close",
	uint8(CIPServiceUploadTransfer):       "upload_transfer",
	uint8(CIPServiceDownloadTransfer):     "download_transfer",
	uint8(CIPServiceClearFile):            "clear_file",
	uint8(CIPServiceReadTagFragmented):    "unconnected_send",
	uint8(CIPServiceWriteTagFragmented):   "write_tag_fragmented",
	uint8(CIPServiceGetInstanceAttrList):  "get_instance_attribute_list",
	uint8(CIPServiceGetConnectionData):    "get_connection_data",
	uint8(CIPServiceSearchConnectionData): "search_connection_data",
	uint8(CIPServiceGetConnectionOwner):   "get_connection_owner",
	uint8(CIPServiceLargeForwardOpen):     "large_forward_open",
	uint8(CIPServiceForwardOpen):          "forward_open",
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
