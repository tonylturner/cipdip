package spec

import "github.com/tturner/cipdip/internal/cip/protocol"

func registerDefaultServices(registry *Registry) {
	registerGenericService := func(code protocol.CIPServiceCode, name string, requiresInstance, requiresAttribute bool, minReq, minResp int) {
		registry.RegisterService(ServiceDef{
			ClassID:           0,
			Service:           code,
			Name:              name,
			RequiresInstance:  requiresInstance,
			RequiresAttribute: requiresAttribute,
			MinRequestLen:     minReq,
			MinResponseLen:    minResp,
		})
	}

	// Core generic services.
	registerGenericService(CIPServiceGetAttributeAll, ServiceName(CIPServiceGetAttributeAll), true, false, 0, 0)
	registerGenericService(CIPServiceSetAttributeAll, ServiceName(CIPServiceSetAttributeAll), true, false, 1, 0)
	registerGenericService(CIPServiceGetAttributeList, ServiceName(CIPServiceGetAttributeList), true, false, 2, 0)
	registerGenericService(CIPServiceSetAttributeList, ServiceName(CIPServiceSetAttributeList), true, false, 2, 0)
	registerGenericService(CIPServiceReset, ServiceName(CIPServiceReset), true, false, 0, 0)
	registerGenericService(CIPServiceStart, ServiceName(CIPServiceStart), true, false, 0, 0)
	registerGenericService(CIPServiceStop, ServiceName(CIPServiceStop), true, false, 0, 0)
	registerGenericService(CIPServiceCreate, ServiceName(CIPServiceCreate), true, false, 0, 0)
	registerGenericService(CIPServiceDelete, ServiceName(CIPServiceDelete), true, false, 0, 0)
	registerGenericService(CIPServiceApplyAttributes, ServiceName(CIPServiceApplyAttributes), true, false, 0, 0)
	registerGenericService(CIPServiceGetAttributeSingle, ServiceName(CIPServiceGetAttributeSingle), true, true, 0, 0)
	registerGenericService(CIPServiceSetAttributeSingle, ServiceName(CIPServiceSetAttributeSingle), true, true, 1, 0)
	registerGenericService(CIPServiceFindNextObjectInst, ServiceName(CIPServiceFindNextObjectInst), true, false, 0, 0)
	registerGenericService(CIPServiceRestore, ServiceName(CIPServiceRestore), true, false, 0, 0)
	registerGenericService(CIPServiceSave, ServiceName(CIPServiceSave), true, false, 0, 0)
	registerGenericService(CIPServiceNoOp, ServiceName(CIPServiceNoOp), true, false, 0, 0)
	registerGenericService(CIPServiceGetMember, ServiceName(CIPServiceGetMember), true, false, 0, 0)
	registerGenericService(CIPServiceSetMember, ServiceName(CIPServiceSetMember), true, false, 1, 0)
	registerGenericService(CIPServiceInsertMember, ServiceName(CIPServiceInsertMember), true, false, 1, 0)
	registerGenericService(CIPServiceRemoveMember, ServiceName(CIPServiceRemoveMember), true, false, 1, 0)
	registerGenericService(CIPServiceGroupSync, ServiceName(CIPServiceGroupSync), true, false, 0, 0)

	// Message Router (Multiple Service Packet).
	registry.RegisterService(ServiceDef{
		ClassID:          CIPClassMessageRouter,
		Service:          CIPServiceMultipleService,
		Name:             ServiceName(CIPServiceMultipleService),
		RequiresInstance: true,
		MinRequestLen:    4,
	})

	// Connection Manager-specific services.
	registry.RegisterService(ServiceDef{
		ClassID:          CIPClassConnectionManager,
		Service:          CIPServiceForwardOpen,
		Name:             ServiceName(CIPServiceForwardOpen),
		RequiresInstance: true,
		MinRequestLen:    20,
		MinResponseLen:   17,
	})
	registry.RegisterService(ServiceDef{
		ClassID:          CIPClassConnectionManager,
		Service:          CIPServiceForwardClose,
		Name:             ServiceName(CIPServiceForwardClose),
		RequiresInstance: true,
		MinRequestLen:    3,
	})
	registry.RegisterService(ServiceDef{
		ClassID:          CIPClassConnectionManager,
		Service:          CIPServiceLargeForwardOpen,
		Name:             ServiceName(CIPServiceLargeForwardOpen),
		RequiresInstance: true,
		MinRequestLen:    20,
		MinResponseLen:   17,
	})
	registry.RegisterService(ServiceDef{
		ClassID:          CIPClassConnectionManager,
		Service:          CIPServiceUnconnectedSend,
		Name:             "Unconnected_Send",
		RequiresInstance: true,
		MinRequestLen:    4,
		MinResponseLen:   2,
		StrictRules:      []Rule{UnconnectedSendRule{}},
	})
	registry.RegisterService(ServiceDef{
		ClassID:          CIPClassConnectionManager,
		Service:          CIPServiceGetConnectionData,
		Name:             ServiceName(CIPServiceGetConnectionData),
		RequiresInstance: true,
	})
	registry.RegisterService(ServiceDef{
		ClassID:          CIPClassConnectionManager,
		Service:          CIPServiceSearchConnectionData,
		Name:             ServiceName(CIPServiceSearchConnectionData),
		RequiresInstance: true,
	})
	registry.RegisterService(ServiceDef{
		ClassID:          CIPClassConnectionManager,
		Service:          CIPServiceGetConnectionOwner,
		Name:             ServiceName(CIPServiceGetConnectionOwner),
		RequiresInstance: true,
	})

	// Symbol Object (Logix tag services).
	registry.RegisterService(ServiceDef{
		ClassID:          CIPClassSymbolObject,
		Service:          CIPServiceReadTag,
		Name:             ServiceName(CIPServiceReadTag),
		RequiresInstance: true,
		MinRequestLen:    2,
	})
	registry.RegisterService(ServiceDef{
		ClassID:          CIPClassSymbolObject,
		Service:          CIPServiceWriteTag,
		Name:             ServiceName(CIPServiceWriteTag),
		RequiresInstance: true,
		MinRequestLen:    4,
	})
	registry.RegisterService(ServiceDef{
		ClassID:          CIPClassSymbolObject,
		Service:          CIPServiceReadTagFragmented,
		Name:             "Read_Tag_Fragmented",
		RequiresInstance: true,
		MinRequestLen:    6,
	})
	registry.RegisterService(ServiceDef{
		ClassID:          CIPClassSymbolObject,
		Service:          CIPServiceWriteTagFragmented,
		Name:             ServiceName(CIPServiceWriteTagFragmented),
		RequiresInstance: true,
		MinRequestLen:    8,
	})
	registry.RegisterService(ServiceDef{
		ClassID:          CIPClassSymbolObject,
		Service:          CIPServiceReadModifyWrite,
		Name:             ServiceName(CIPServiceReadModifyWrite),
		RequiresInstance: true,
		MinRequestLen:    4,
	})

	// Template Object (Logix template read).
	registry.RegisterService(ServiceDef{
		ClassID:          CIPClassTemplateObject,
		Service:          CIPServiceReadTag,
		Name:             "Template_Read",
		RequiresInstance: true,
		MinRequestLen:    6,
	})

	// PCCC Object.
	registry.RegisterService(ServiceDef{
		ClassID:          CIPClassPCCCObject,
		Service:          CIPServiceExecutePCCC,
		Name:             ServiceName(CIPServiceExecutePCCC),
		RequiresInstance: true,
		MinRequestLen:    1,
	})

	// File Object services.
	for _, code := range []protocol.CIPServiceCode{
		CIPServiceInitiateUpload,
		CIPServiceInitiateDownload,
		CIPServiceInitiatePartialRead,
		CIPServiceInitiatePartialWrite,
		CIPServiceUploadTransfer,
		CIPServiceDownloadTransfer,
		CIPServiceClearFile,
	} {
		minReq := 1
		if code == CIPServiceClearFile {
			minReq = 0
		}
		registry.RegisterService(ServiceDef{
			ClassID:          CIPClassFileObject,
			Service:          code,
			Name:             ServiceName(code),
			RequiresInstance: true,
			MinRequestLen:    minReq,
		})
	}

	// Modbus Object services.
	for _, code := range []protocol.CIPServiceCode{0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51} {
		registry.RegisterService(ServiceDef{
			ClassID:          CIPClassModbus,
			Service:          code,
			Name:             ServiceName(code),
			RequiresInstance: true,
			MinRequestLen:    1,
		})
	}
}
