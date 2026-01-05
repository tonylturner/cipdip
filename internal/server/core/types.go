package core

import (
	"context"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/logging"
	"github.com/tturner/cipdip/internal/server/handlers"
)

// Server represents an EtherNet/IP CIP server.
type Server struct {
	config          *config.ServerConfig
	logger          *logging.Logger
	tcpListener     *net.TCPListener
	udpListener     *net.UDPConn
	metricsListener net.Listener
	sessions        map[uint32]*Session
	sessionsMu      sync.RWMutex
	connections     map[uint32]*ConnectionState
	connectionsMu   sync.RWMutex
	nextSessionID   uint32
	handlers        *handlers.Registry
	enipSupport     enipSupportConfig
	sessionPolicy   enipSessionPolicy
	cipPolicy       cipPolicyConfig
	faults          faultPolicy
	coalesceMu      sync.Mutex
	coalesceQueue   map[*net.TCPConn][]byte
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
}

// Session represents an active EtherNet/IP session.
type Session struct {
	ID           uint32
	Conn         *net.TCPConn
	RemoteIP     string
	CreatedAt    time.Time
	LastActivity time.Time
	mu           sync.Mutex
}

// ConnectionState tracks ForwardOpen connection state.
type ConnectionState struct {
	ID           uint32
	SessionID    uint32
	CreatedAt    time.Time
	LastActivity time.Time
	RemoteAddr   string
}

type enipSupportConfig struct {
	listIdentity    bool
	listServices    bool
	listInterfaces  bool
	registerSession bool
	sendRRData      bool
	sendUnitData    bool
}

type enipSessionPolicy struct {
	requireRegister  bool
	maxSessions      int
	maxSessionsPerIP int
	idleTimeout      time.Duration
}

type cipPolicyConfig struct {
	strictPaths        bool
	defaultStatus      uint8
	defaultExtStatus   uint16
	allowRules         []config.ServerCIPRule
	denyRules          []config.ServerCIPRule
	denyStatusOverride []config.ServerCIPStatusOverride
}

type faultPolicy struct {
	enabled bool

	latencyBase   time.Duration
	latencyJitter time.Duration
	spikeEveryN   int
	spikeDelay    time.Duration

	dropEveryN  int
	dropPct     float64
	closeEveryN int
	stallEveryN int

	chunkWrites     bool
	chunkMin        int
	chunkMax        int
	interChunkDelay time.Duration
	coalesce        bool

	mu            sync.Mutex
	responseCount int
	rng           *rand.Rand
}

type responseFaultAction struct {
	drop     bool
	delay    time.Duration
	close    bool
	chunked  bool
	coalesce bool
}
