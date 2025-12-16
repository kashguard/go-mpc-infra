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

// CreateDKGSessionRequest 创建DKG会话请求
type CreateDKGSessionRequest struct {
	KeyID      string
	Algorithm  string
	Curve      string
	Protocol   string
	Threshold  int
	TotalNodes int
	NodeIDs    []string // 可选的参与节点列表，如果为空则自动发现
}

// DKGSession DKG会话
type DKGSession struct {
	SessionID          string
	KeyID              string
	Protocol           string
	Status             string
	Threshold          int
	TotalNodes         int
	ParticipatingNodes []string
	CurrentRound       int
	TotalRounds        int
	PublicKey          string // DKG完成后生成的公钥
	CreatedAt          time.Time
	CompletedAt        *time.Time
	DurationMs         int
	ExpiresAt          time.Time
}

// NotifyDKGRequest 通知参与者DKG请求
type NotifyDKGRequest struct {
	SessionID  string
	KeyID      string
	Algorithm  string
	Curve      string
	Protocol   string
	Threshold  int
	TotalNodes int
	NodeIDs    []string
}
