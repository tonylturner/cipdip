package core

import (
	"fmt"
	"net"
	"time"
)

func (s *Server) trackConnection(connID uint32, sessionID uint32, remoteAddr string) {
	if connID == 0 {
		return
	}
	state := &ConnectionState{
		ID:           connID,
		SessionID:    sessionID,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		RemoteAddr:   remoteAddr,
	}
	s.connectionsMu.Lock()
	s.connections[connID] = state
	s.connectionsMu.Unlock()
}

func (s *Server) untrackConnection(connID uint32) {
	s.connectionsMu.Lock()
	delete(s.connections, connID)
	s.connectionsMu.Unlock()
}

func (s *Server) touchConnection(connID uint32) {
	s.connectionsMu.Lock()
	if state, ok := s.connections[connID]; ok {
		state.LastActivity = time.Now()
	}
	s.connectionsMu.Unlock()
}

func (s *Server) dropConnectionsForSession(sessionID uint32) {
	s.connectionsMu.Lock()
	for connID, state := range s.connections {
		if state != nil && state.SessionID == sessionID {
			delete(s.connections, connID)
		}
	}
	s.connectionsMu.Unlock()
}

func (s *Server) isConnectionActive(connID uint32, sessionID uint32) bool {
	s.connectionsMu.RLock()
	state, ok := s.connections[connID]
	s.connectionsMu.RUnlock()
	if !ok || state == nil {
		return false
	}
	if state.SessionID != sessionID {
		return false
	}

	timeout := time.Duration(s.config.Server.ConnectionTimeoutMs) * time.Millisecond
	if timeout > 0 && time.Since(state.LastActivity) > timeout {
		s.untrackConnection(connID)
		return false
	}

	return true
}

func (s *Server) requireSession(sessionID uint32, remoteAddr string) (*Session, bool) {
	if !s.sessionPolicy.requireRegister && sessionID == 0 {
		return nil, true
	}

	s.sessionsMu.RLock()
	session, ok := s.sessions[sessionID]
	s.sessionsMu.RUnlock()

	if !ok || session == nil {
		s.logger.Error("SendRRData with invalid session %d from %s", sessionID, remoteAddr)
		return nil, false
	}
	if session.LastActivity.IsZero() {
		session.LastActivity = time.Now()
	}
	if s.sessionPolicy.idleTimeout > 0 && time.Since(session.LastActivity) > s.sessionPolicy.idleTimeout {
		s.sessionsMu.Lock()
		delete(s.sessions, sessionID)
		s.sessionsMu.Unlock()
		return nil, false
	}
	return session, true
}

func (s *Server) enforceSessionLimits(remoteAddr string) error {
	maxSessions := s.sessionPolicy.maxSessions
	maxSessionsPerIP := s.sessionPolicy.maxSessionsPerIP
	if maxSessions <= 0 && maxSessionsPerIP <= 0 {
		return nil
	}

	targetIP := remoteIP(remoteAddr)
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	if maxSessions > 0 && len(s.sessions) >= maxSessions {
		return fmt.Errorf("max sessions reached")
	}
	if maxSessionsPerIP > 0 && targetIP != "" {
		count := 0
		for _, session := range s.sessions {
			if session != nil && session.RemoteIP == targetIP {
				count++
			}
		}
		if count >= maxSessionsPerIP {
			return fmt.Errorf("max sessions per IP reached")
		}
	}
	return nil
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
