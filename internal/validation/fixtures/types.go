package fixtures

import (
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/validation"
)

type PacketExpectation = validation.PacketExpectation
type ValidationManifest = validation.ValidationManifest

const (
	ServiceShapeNone            = validation.ServiceShapeNone
	ServiceShapePayload         = validation.ServiceShapePayload
	ServiceShapeRead            = validation.ServiceShapeRead
	ServiceShapeWrite           = validation.ServiceShapeWrite
	ServiceShapeFragmented      = validation.ServiceShapeFragmented
	ServiceShapeForwardOpen     = validation.ServiceShapeForwardOpen
	ServiceShapeForwardClose    = validation.ServiceShapeForwardClose
	ServiceShapeUnconnectedSend = validation.ServiceShapeUnconnectedSend
	ServiceShapeRockwellTag     = validation.ServiceShapeRockwellTag
	ServiceShapeRockwellTagFrag = validation.ServiceShapeRockwellTagFrag
	ServiceShapeTemplate        = validation.ServiceShapeTemplate
	ServiceShapePCCC            = validation.ServiceShapePCCC
	ServiceShapeFileObject      = validation.ServiceShapeFileObject
	ServiceShapeModbus          = validation.ServiceShapeModbus
	ServiceShapeSafetyReset     = validation.ServiceShapeSafetyReset
)

type ValidationRequestSpec struct {
	Name            string
	Req             protocol.CIPRequest
	PayloadType     string
	PayloadParams   map[string]any
	ServiceShape    string
	IncludeResponse bool
	ExpectSymbol    bool
	Outcome         string
	ResponseOutcome string
	TrafficMode     string
}

type ValidationPCAPSpec struct {
	Name     string
	Requests []ValidationRequestSpec
}

type ValidationPacket struct {
	Data   []byte
	Expect PacketExpectation
}
