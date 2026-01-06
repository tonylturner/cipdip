package core

import (
	"context"
	"fmt"
	"net"

	cipclient "github.com/tturner/cipdip/internal/cip/client"
	"github.com/tturner/cipdip/internal/cip/spec"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/logging"
	"github.com/tturner/cipdip/internal/server/handlers"
	"github.com/tturner/cipdip/internal/server/handlers/standard"
	"github.com/tturner/cipdip/internal/server/handlers/vendors/rockwell"
)

// NewServer creates a new CIP server.
func NewServer(cfg *config.ServerConfig, logger *logging.Logger) (*Server, error) {
	registry := handlers.NewRegistry()

	identityHandler := standard.NewIdentityHandler(cfg)
	registry.RegisterHandler(spec.CIPClassIdentityObject, uint8(spec.CIPServiceGetAttributeSingle), identityHandler)
	registry.RegisterHandler(spec.CIPClassIdentityObject, uint8(spec.CIPServiceGetAttributeAll), identityHandler)

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

	default:
		return nil, fmt.Errorf("unknown personality: %s", cfg.Server.Personality)
	}

	ctx, cancel := context.WithCancel(context.Background())

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
	}

	return s, nil
}

func buildProfileClassSet(profiles []string, overrides map[string][]uint16) map[uint16]struct{} {
	classList := cipclient.ResolveCIPProfileClasses(cipclient.NormalizeCIPProfiles(profiles), overrides)
	out := make(map[uint16]struct{}, len(classList))
	for _, classID := range classList {
		out[classID] = struct{}{}
	}
	return out
}
