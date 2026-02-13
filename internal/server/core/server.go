package core

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/tonylturner/cipdip/internal/cip/catalog"
	cipclient "github.com/tonylturner/cipdip/internal/cip/client"
	"github.com/tonylturner/cipdip/internal/cip/spec"
	"github.com/tonylturner/cipdip/internal/config"
	"github.com/tonylturner/cipdip/internal/logging"
	"github.com/tonylturner/cipdip/internal/modbus"
	"github.com/tonylturner/cipdip/internal/server/handlers"
	"github.com/tonylturner/cipdip/internal/server/handlers/standard"
	"github.com/tonylturner/cipdip/internal/server/handlers/vendors/rockwell"
)

// NewServer creates a new CIP server.
func NewServer(cfg *config.ServerConfig, logger *logging.Logger) (*Server, error) {
	registry := handlers.NewRegistry()

	identityHandler := standard.NewIdentityHandler(cfg)
	registry.RegisterHandler(spec.CIPClassIdentityObject, uint8(spec.CIPServiceGetAttributeSingle), identityHandler)
	registry.RegisterHandler(spec.CIPClassIdentityObject, uint8(spec.CIPServiceGetAttributeAll), identityHandler)

	// Register Connection Manager stubs for unsupported services
	connMgrStubs := standard.NewConnectionManagerStubs()
	registry.RegisterHandler(spec.CIPClassConnectionManager, uint8(spec.CIPServiceGetConnectionData), connMgrStubs)
	registry.RegisterHandler(spec.CIPClassConnectionManager, uint8(spec.CIPServiceSearchConnectionData), connMgrStubs)
	registry.RegisterHandler(spec.CIPClassConnectionManager, uint8(spec.CIPServiceGetConnectionOwner), connMgrStubs)

	profileClasses := buildProfileClassSet(cfg.CIPProfiles, cfg.CIPProfileClasses)
	genericHandler := standard.NewGenericObjectHandler(profileClasses)
	registry.Register(handlers.ClassAny, handlers.ServiceAny, genericHandler.HandleCIPRequest)

	switch cfg.Server.Personality {
	case "adapter":
		adapterHandler, err := standard.NewAdapterPersonality(cfg, logger)
		if err != nil {
			return nil, fmt.Errorf("create adapter personality: %w", err)
		}
		registry.RegisterHandler(spec.CIPClassAssembly, handlers.ServiceAny, adapterHandler)

	case "logix_like":
		logixHandler, err := rockwell.NewLogixPersonality(cfg, logger)
		if err != nil {
			return nil, fmt.Errorf("create logix personality: %w", err)
		}
		registry.RegisterHandler(handlers.ClassAny, handlers.ServiceAny, logixHandler)

	case "pccc":
		pcccHandler, err := standard.NewPCCCPersonality(cfg, logger)
		if err != nil {
			return nil, fmt.Errorf("create pccc personality: %w", err)
		}
		registry.RegisterHandler(spec.CIPClassPCCCObject, handlers.ServiceAny, pcccHandler)

	default:
		return nil, fmt.Errorf("unknown personality: %s", cfg.Server.Personality)
	}

	// Register PCCC handler alongside primary personality when data tables are configured.
	if cfg.Server.Personality != "pccc" && len(cfg.PCCCDataTables) > 0 {
		pcccHandler, err := standard.NewPCCCPersonality(cfg, logger)
		if err != nil {
			return nil, fmt.Errorf("create pccc handler: %w", err)
		}
		registry.RegisterHandler(spec.CIPClassPCCCObject, handlers.ServiceAny, pcccHandler)
		logger.Info("Registered PCCC handler (class 0x%04X) alongside %s personality", spec.CIPClassPCCCObject, cfg.Server.Personality)
	}

	// Register Modbus CIP tunnel handler (class 0x44) if enabled.
	if cfg.ModbusConfig.Enabled {
		modbusStore := buildModbusDataStore(cfg)
		modbusHandler := handlers.NewModbusHandler(modbusStore, logger)
		registry.RegisterHandler(spec.CIPClassModbus, handlers.ServiceAny, modbusHandler)
		logger.Info("Registered Modbus CIP handler (class 0x%04X)", spec.CIPClassModbus)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Determine personality for catalog filtering
	var personality catalog.Personality
	switch cfg.Server.Personality {
	case "adapter":
		personality = catalog.PersonalityAdapter
	case "logix_like":
		personality = catalog.PersonalityLogixLike
	case "pccc":
		personality = catalog.PersonalityPCCC
	default:
		personality = catalog.PersonalityAny
	}

	// Try to load catalog for service validation (optional - server works without it)
	var cat *catalog.Catalog
	cwd, _ := os.Getwd()
	if catalogPath, err := catalog.FindCoreCatalog(cwd); err == nil {
		if file, err := catalog.Load(catalogPath); err == nil {
			cat = catalog.NewCatalog(file)
			logger.Info("Loaded CIP service catalog from %s (%d entries)", catalogPath, len(file.Entries))
		}
	}

	s := &Server{
		config:        cfg,
		logger:        logger,
		sessions:      make(map[uint32]*Session),
		connections:   make(map[uint32]*ConnectionState),
		nextSessionID: 1,
		handlers:      registry,
		enipSupport:   resolveENIPSupport(cfg),
		sessionPolicy: resolveSessionPolicy(cfg),
		cipPolicy:     resolveCIPPolicy(cfg),
		faults:        resolveFaultPolicy(cfg),
		coalesceQueue: make(map[*net.TCPConn][]byte),
		ctx:           ctx,
		cancel:        cancel,
		catalog:       cat,
		personality:   personality,
	}

	return s, nil
}

func buildModbusDataStore(cfg *config.ServerConfig) *modbus.DataStore {
	mc := cfg.ModbusConfig
	dsCfg := modbus.DefaultDataStoreConfig()
	if mc.CoilCount > 0 {
		dsCfg.CoilCount = mc.CoilCount
	}
	if mc.DiscreteInputCount > 0 {
		dsCfg.DiscreteInputCount = mc.DiscreteInputCount
	}
	if mc.InputRegisterCount > 0 {
		dsCfg.InputRegisterCount = mc.InputRegisterCount
	}
	if mc.HoldingRegisterCount > 0 {
		dsCfg.HoldingRegisterCount = mc.HoldingRegisterCount
	}
	return modbus.NewDataStore(dsCfg)
}

func buildProfileClassSet(profiles []string, overrides map[string][]uint16) map[uint16]struct{} {
	classList := cipclient.ResolveCIPProfileClasses(cipclient.NormalizeCIPProfiles(profiles), overrides)
	out := make(map[uint16]struct{}, len(classList))
	for _, classID := range classList {
		out[classID] = struct{}{}
	}
	return out
}
