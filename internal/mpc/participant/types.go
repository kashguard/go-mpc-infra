package participant

// KeyShare 密钥分片
type KeyShare struct {
	KeyID  string
	NodeID string
	Share  []byte
	Index  int
}

// SignatureShare 签名分片
type SignatureShare struct {
	SessionID string
	NodeID    string
	Share     []byte
	Round     int
}
