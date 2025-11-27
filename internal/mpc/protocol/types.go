package protocol

// PublicKey 公钥
type PublicKey struct {
	Bytes []byte
	Hex   string
}

// KeyShare 密钥分片
type KeyShare struct {
	ShareID string
	NodeID  string
	Share   []byte
	Index   int
}

// Signature 签名
type Signature struct {
	R     []byte
	S     []byte
	Bytes []byte
	Hex   string
}

// SignatureShare 签名分片
type SignatureShare struct {
	ShareID string
	NodeID  string
	Share   []byte
	Index   int
}

// KeyGenRequest 密钥生成请求
type KeyGenRequest struct {
	Algorithm  string
	Curve      string
	Threshold  int
	TotalNodes int
	NodeIDs    []string
}

// KeyGenResponse 密钥生成响应
type KeyGenResponse struct {
	KeyShares map[string]*KeyShare
	PublicKey *PublicKey
}

// SignRequest 签名请求
type SignRequest struct {
	KeyID      string
	Message    []byte
	MessageHex string
	NodeIDs    []string
}

// SignResponse 签名响应
type SignResponse struct {
	Signature *Signature
	PublicKey *PublicKey
}

// ProtocolMessage 协议消息
type ProtocolMessage struct {
	Type      string
	SessionID string
	FromNode  string
	ToNode    string
	Round     int
	Data      []byte
	Timestamp int64
}
