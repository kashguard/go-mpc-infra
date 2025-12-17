package protocol

import (
	"fmt"
	"strings"
)

// ProtocolError represents a generic protocol error
type ProtocolError struct {
	Type      ErrorType
	Message   string
	SessionID string
	Culprits  []string // Node IDs of malicious or faulty parties
	Original  error
}

type ErrorType int

const (
	ErrTypeUnknown ErrorType = iota
	ErrTypeTimeout
	ErrTypeNetwork
	ErrTypeMalicious
	ErrTypeResource
)

func (e *ProtocolError) Error() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[%s] %s", e.Type.String(), e.Message))
	if len(e.Culprits) > 0 {
		sb.WriteString(fmt.Sprintf(" (culprits: %v)", e.Culprits))
	}
	if e.SessionID != "" {
		sb.WriteString(fmt.Sprintf(" [session: %s]", e.SessionID))
	}
	if e.Original != nil {
		sb.WriteString(fmt.Sprintf(": %v", e.Original))
	}
	return sb.String()
}

func (e *ProtocolError) Unwrap() error {
	return e.Original
}

func (t ErrorType) String() string {
	switch t {
	case ErrTypeTimeout:
		return "TIMEOUT"
	case ErrTypeNetwork:
		return "NETWORK"
	case ErrTypeMalicious:
		return "MALICIOUS"
	case ErrTypeResource:
		return "RESOURCE"
	default:
		return "UNKNOWN"
	}
}

// NewTimeoutError creates a new timeout error
func NewTimeoutError(sessionID string, msg string) *ProtocolError {
	return &ProtocolError{
		Type:      ErrTypeTimeout,
		Message:   msg,
		SessionID: sessionID,
	}
}

// NewMaliciousNodeError creates a new malicious node error
func NewMaliciousNodeError(sessionID string, culprits []string, msg string) *ProtocolError {
	return &ProtocolError{
		Type:      ErrTypeMalicious,
		Message:   msg,
		SessionID: sessionID,
		Culprits:  culprits,
	}
}

// NewNetworkError creates a new network error
func NewNetworkError(sessionID string, err error) *ProtocolError {
	return &ProtocolError{
		Type:      ErrTypeNetwork,
		Message:   "network error",
		SessionID: sessionID,
		Original:  err,
	}
}
