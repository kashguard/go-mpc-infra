package coordinator

import "time"

// CreateSessionRequest 创建会话请求
type CreateSessionRequest struct {
	KeyID    string
	Message  []byte
	Protocol string
	Timeout  int
}

// SigningSession 签名会话
type SigningSession struct {
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

// Signature 签名
type Signature struct {
	R     []byte
	S     []byte
	Bytes []byte
	Hex   string
}
