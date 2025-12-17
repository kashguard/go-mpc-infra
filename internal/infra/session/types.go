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

// RoundProgress 描述协议轮次的最新状态
type RoundProgress struct {
	SessionID   string
	KeyID       string
	Protocol    string
	Status      SessionStatus
	Threshold   int
	TotalNodes  int
	Round       int
	TotalRounds int
	NodeIDs     []string
	Message     string
	Duration    time.Duration
	UpdatedAt   time.Time
	ExpiresAt   time.Time
}

// WALRecord 记录尚未提交的协议事件（用于恢复/重放）
type WALRecord struct {
	Sequence  int64
	SessionID string
	Round     int
	Payload   []byte
	CreatedAt time.Time
}
