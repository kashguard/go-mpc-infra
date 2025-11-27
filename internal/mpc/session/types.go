package session

import "time"

// Session 签名会话
type Session struct {
	SessionID          string
	KeyID              string
	Protocol           string
	Status             string
	Threshold          int
	TotalNodes         int
	ParticipatingNodes []string
	CurrentRound       int
	TotalRounds        int
	Signature          string
	CreatedAt          time.Time
	CompletedAt        *time.Time
	DurationMs         int
	ExpiresAt          time.Time
}

// SessionStatus 会话状态
type SessionStatus string

const (
	SessionStatusPending   SessionStatus = "pending"
	SessionStatusActive    SessionStatus = "active"
	SessionStatusCompleted SessionStatus = "completed"
	SessionStatusFailed    SessionStatus = "failed"
	SessionStatusCancelled SessionStatus = "cancelled"
	SessionStatusTimeout   SessionStatus = "timeout"
)
