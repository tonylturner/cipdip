package cipclient

import (
	"encoding/binary"

	clientpkg "github.com/tturner/cipdip/internal/cip/client"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/enip"
)

// ProtocolProfile and related helpers are forwarded to the new client package.
type ProtocolProfile = clientpkg.ProtocolProfile

var (
	StrictODVAProfile  = clientpkg.StrictODVAProfile
	LegacyCompatProfile = clientpkg.LegacyCompatProfile
	VendorProfiles     = clientpkg.VendorProfiles
)

func CurrentProtocolProfile() ProtocolProfile {
	return clientpkg.CurrentProtocolProfile()
}

func SetProtocolProfile(profile ProtocolProfile) {
	clientpkg.SetProtocolProfile(profile)
}

func ResolveProtocolProfile(mode, variant, enipEndian, cipEndian string, cipPathSize, cipRespReserved, useCPF *bool, ioSequenceMode string) ProtocolProfile {
	return clientpkg.ResolveProtocolProfile(mode, variant, enipEndian, cipEndian, cipPathSize, cipRespReserved, useCPF, ioSequenceMode)
}

func NormalizeCIPProfiles(profiles []string) []string {
	return clientpkg.NormalizeCIPProfiles(profiles)
}

func ResolveCIPProfileClasses(profiles []string, overrides map[string][]uint16) []uint16 {
	return clientpkg.ResolveCIPProfileClasses(profiles, overrides)
}

// Client types.
type Client = clientpkg.Client
type ENIPClient = clientpkg.ENIPClient
type ConnectionParams = clientpkg.ConnectionParams
type IOConnection = clientpkg.IOConnection
type UnconnectedSendOptions = clientpkg.UnconnectedSendOptions
type PayloadSpec = clientpkg.PayloadSpec
type PayloadResult = clientpkg.PayloadResult
type PayloadMutation = clientpkg.PayloadMutation
type PayloadType = clientpkg.PayloadType
type PacketValidator = clientpkg.PacketValidator

const (
	PayloadNone             = clientpkg.PayloadNone
	PayloadForwardOpen      = clientpkg.PayloadForwardOpen
	PayloadForwardClose     = clientpkg.PayloadForwardClose
	PayloadUnconnectedSend  = clientpkg.PayloadUnconnectedSend
	PayloadRockwellTag      = clientpkg.PayloadRockwellTag
	PayloadRockwellTagFrag  = clientpkg.PayloadRockwellTagFrag
	PayloadRockwellTemplate = clientpkg.PayloadRockwellTemplate
	PayloadRockwellPCCC     = clientpkg.PayloadRockwellPCCC
	PayloadFileObject       = clientpkg.PayloadFileObject
	PayloadModbusObject     = clientpkg.PayloadModbusObject
	PayloadSafetyReset      = clientpkg.PayloadSafetyReset
	PayloadEnergyMetering   = clientpkg.PayloadEnergyMetering
	PayloadMotionAxis       = clientpkg.PayloadMotionAxis
)

func NewClient() *ENIPClient {
	client, _ := clientpkg.NewClient().(*clientpkg.ENIPClient)
	return client
}

func BuildServicePayload(req protocol.CIPRequest, spec PayloadSpec) (PayloadResult, error) {
	return clientpkg.BuildServicePayload(req, spec)
}

func ApplyPayloadMutation(payload []byte, mutation PayloadMutation) []byte {
	return clientpkg.ApplyPayloadMutation(payload, mutation)
}

func NewPacketValidator(strict bool) *PacketValidator {
	return clientpkg.NewPacketValidator(strict)
}

func BuildForwardOpenRequest(params ConnectionParams) ([]byte, error) {
	return clientpkg.BuildForwardOpenRequest(params)
}

func BuildForwardCloseRequest(connectionID uint32) ([]byte, error) {
	return clientpkg.BuildForwardCloseRequest(connectionID)
}

func BuildForwardOpenPayload(params ConnectionParams) ([]byte, error) {
	return clientpkg.BuildForwardOpenPayload(params)
}

func BuildForwardClosePayload(connectionID uint32) ([]byte, error) {
	return clientpkg.BuildForwardClosePayload(connectionID)
}

func ParseForwardOpenResponse(data []byte) (connectionID uint32, oToTConnID uint32, tToOConnID uint32, err error) {
	return clientpkg.ParseForwardOpenResponse(data)
}

func ParseForwardCloseResponse(data []byte) error {
	return clientpkg.ParseForwardCloseResponse(data)
}

func BuildUnconnectedSendPayload(messageRequest []byte, opts UnconnectedSendOptions) ([]byte, error) {
	return clientpkg.BuildUnconnectedSendPayload(messageRequest, opts)
}

func BuildUnconnectedSendResponsePayload(messageResponse []byte) []byte {
	return clientpkg.BuildUnconnectedSendResponsePayload(messageResponse)
}

func BuildMultipleServiceRequest(requests []protocol.CIPRequest) (protocol.CIPRequest, error) {
	return clientpkg.BuildMultipleServiceRequest(requests)
}

func BuildMultipleServiceRequestPayload(requests []protocol.CIPRequest) ([]byte, error) {
	return clientpkg.BuildMultipleServiceRequestPayload(requests)
}

func ParseMultipleServiceRequestPayload(payload []byte) ([]protocol.CIPRequest, error) {
	return clientpkg.ParseMultipleServiceRequestPayload(payload)
}

func BuildMultipleServiceResponsePayload(responses []protocol.CIPResponse) ([]byte, error) {
	return clientpkg.BuildMultipleServiceResponsePayload(responses)
}

func ParseMultipleServiceResponsePayload(payload []byte, path protocol.CIPPath) ([]protocol.CIPResponse, error) {
	return clientpkg.ParseMultipleServiceResponsePayload(payload, path)
}

func BuildReadTagPayload(elementCount uint16) []byte {
	return clientpkg.BuildReadTagPayload(elementCount)
}

func BuildReadTagFragmentedPayload(elementCount uint16, offset uint32) []byte {
	return clientpkg.BuildReadTagFragmentedPayload(elementCount, offset)
}

func BuildWriteTagPayload(typeCode uint16, elementCount uint16, data []byte) []byte {
	return clientpkg.BuildWriteTagPayload(typeCode, elementCount, data)
}

func BuildWriteTagFragmentedPayload(typeCode uint16, elementCount uint16, offset uint32, data []byte) []byte {
	return clientpkg.BuildWriteTagFragmentedPayload(typeCode, elementCount, offset, data)
}

func BuildListServices(senderContext [8]byte) []byte {
	return clientpkg.BuildListServices(senderContext)
}

func BuildListInterfaces(senderContext [8]byte) []byte {
	return clientpkg.BuildListInterfaces(senderContext)
}

func ParseListServicesResponse(data []byte) ([]enip.CPFItem, error) {
	return clientpkg.ParseListServicesResponse(data)
}

func ParseListInterfacesResponse(data []byte) ([]enip.CPFItem, error) {
	return clientpkg.ParseListInterfacesResponse(data)
}

// currentENIPByteOrder mirrors client byte-order helpers for validation.
func currentENIPByteOrder() binary.ByteOrder {
	return clientpkg.CurrentProtocolProfile().ENIPByteOrder
}

func currentCIPByteOrder() binary.ByteOrder {
	return clientpkg.CurrentProtocolProfile().CIPByteOrder
}

func isValidENIPCommand(cmd uint16) bool {
	switch cmd {
	case enip.ENIPCommandRegisterSession,
		enip.ENIPCommandUnregisterSession,
		enip.ENIPCommandSendRRData,
		enip.ENIPCommandSendUnitData,
		enip.ENIPCommandListIdentity,
		enip.ENIPCommandListServices,
		enip.ENIPCommandListInterfaces:
		return true
	default:
		return false
	}
}
