package server

import (
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/logging"
	"github.com/tturner/cipdip/internal/server/core"
)

type Server = core.Server

func NewServer(cfg *config.ServerConfig, logger *logging.Logger) (*core.Server, error) {
	return core.NewServer(cfg, logger)
}
