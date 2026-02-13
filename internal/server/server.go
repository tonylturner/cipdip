package server

import (
	"github.com/tonylturner/cipdip/internal/config"
	"github.com/tonylturner/cipdip/internal/logging"
	"github.com/tonylturner/cipdip/internal/server/core"
)

type Server = core.Server

func NewServer(cfg *config.ServerConfig, logger *logging.Logger) (*core.Server, error) {
	return core.NewServer(cfg, logger)
}
