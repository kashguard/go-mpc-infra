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
	KeyID      string
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

// DKGCommitment 表示某一轮的承诺
type DKGCommitment struct {
	SessionID string
	NodeID    string
	Round     int
	Payload   []byte
	Timestamp int64
}

// DKGShareMessage 表示节点之间传递的分片信息
type DKGShareMessage struct {
	SessionID string
	FromNode  string
	ToNode    string
	Round     int
	Share     *KeyShare
	Proof     []byte
}

// DKGState 描述当前DKG执行状态
type DKGState struct {
	SessionID    string
	KeyID        string
	Protocol     string
	CurrentRound int
	TotalRounds  int
	Commitments  map[string]*DKGCommitment
	Shares       map[string]*KeyShare
	PublicKey    *PublicKey
}

// SignRequest 签名请求
type SignRequest struct {
	KeyID           string
	Message         []byte
	MessageHex      string
	NodeIDs         []string
	DerivationPath  string
	ParentChainCode []byte // Root chain code for derivation
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