package logger

import (
	"time"
)

// SecurityLogger wraps Logger for security-relevant events.
// It writes to a separate security.log file for easier incident response monitoring.
type SecurityLogger struct {
	*Logger
}

// NewSecurityLogger creates a SecurityLogger that writes to security.log.
// Uses smaller rotation size (10MB) and keeps more files (30) for better audit trail.
func NewSecurityLogger(dir string) (*SecurityLogger, error) {
	log, err := New(dir, "security.log", 10, 30)
	if err != nil {
		return nil, err
	}
	return &SecurityLogger{Logger: log}, nil
}

// LogThrottled logs a connection throttling event when the connection limit is reached.
func (sl *SecurityLogger) LogThrottled(remoteAddr string, port int) {
	event := map[string]interface{}{
		"event_type":  "connection_throttled",
		"ts":          time.Now().UTC().Format(time.RFC3339),
		"remote_addr": remoteAddr,
		"port":        port,
	}
	sl.WriteEvent(event)
}

// LogConflict logs a port conflict detection event.
func (sl *SecurityLogger) LogConflict(ports []int) {
	event := map[string]interface{}{
		"event_type": "conflict_detected",
		"ts":         time.Now().UTC().Format(time.RFC3339),
		"ports":      ports,
	}
	sl.WriteEvent(event)
}
