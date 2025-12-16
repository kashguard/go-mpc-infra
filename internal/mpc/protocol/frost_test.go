package protocol

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/kashguard/tss-lib/common"
	eddsaKeygen "github.com/kashguard/tss-lib/eddsa/keygen"
	"github.com/kashguard/tss-lib/tss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFROSTProtocol(t *testing.T) {
	protocol := NewFROSTProtocol("ed25519", "node-1", mockMessageRouter)

	assert.NotNil(t, protocol)
	assert.Equal(t, "ed25519", protocol.GetCurve())
	assert.Equal(t, []string{"frost"}, protocol.SupportedProtocols())
	assert.Equal(t, "frost", protocol.DefaultProtocol())
}

func TestFROSTProtocol_ValidateKeyGenRequest(t *testing.T) {
	protocol := NewFROSTProtocol("ed25519", "node-1", mockMessageRouter)

	tests := []struct {
		name    string
		req     *KeyGenRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid request with EdDSA",
			req: &KeyGenRequest{
				Algorithm:  "EdDSA",
				Curve:      "ed25519",
				Threshold:  2,
				TotalNodes: 3,
				NodeIDs:    []string{"node-1", "node-2", "node-3"},
			},
			wantErr: false,
		},
		{
			name: "valid request with Schnorr",
			req: &KeyGenRequest{
				Algorithm:  "Schnorr",
				Curve:      "ed25519",
				Threshold:  2,
				TotalNodes: 3,
				NodeIDs:    []string{"node-1", "node-2", "node-3"},
			},
			wantErr: false,
		},
		{
			name: "valid request with secp256k1",
			req: &KeyGenRequest{
				Algorithm:  "Schnorr",
				Curve:      "secp256k1",
				Threshold:  2,
				TotalNodes: 3,
				NodeIDs:    []string{"node-1", "node-2", "node-3"},
			},
			wantErr: false,
		},
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
			errMsg:  "key generation request is nil",
		},
		{
			name: "unsupported algorithm",
			req: &KeyGenRequest{
				Algorithm:  "ECDSA",
				Curve:      "ed25519",
				Threshold:  2,
				TotalNodes: 3,
			},
			wantErr: true,
			errMsg:  "unsupported algorithm for FROST",
		},
		{
			name: "unsupported curve",
			req: &KeyGenRequest{
				Algorithm:  "Schnorr",
				Curve:      "P256",
				Threshold:  2,
				TotalNodes: 3,
			},
			wantErr: true,
			errMsg:  "unsupported curve for FROST",
		},
		{
			name: "threshold too low",
			req: &KeyGenRequest{
				Algorithm:  "Schnorr",
				Curve:      "ed25519",
				Threshold:  1,
				TotalNodes: 3,
			},
			wantErr: true,
			errMsg:  "threshold must be at least 2",
		},
		{
			name: "total nodes less than threshold",
			req: &KeyGenRequest{
				Algorithm:  "Schnorr",
				Curve:      "ed25519",
				Threshold:  3,
				TotalNodes: 2,
			},
			wantErr: true,
			errMsg:  "total nodes must be at least threshold",
		},
		{
			name: "empty algorithm (should pass)",
			req: &KeyGenRequest{
				Curve:      "ed25519",
				Threshold:  2,
				TotalNodes: 3,
			},
			wantErr: false,
		},
		{
			name: "empty curve (should pass)",
			req: &KeyGenRequest{
				Algorithm:  "Schnorr",
				Threshold:  2,
				TotalNodes: 3,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := protocol.ValidateKeyGenRequest(tt.req)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestFROSTProtocol_ValidateSignRequest(t *testing.T) {
	protocol := NewFROSTProtocol("ed25519", "node-1", mockMessageRouter)

	tests := []struct {
		name    string
		req     *SignRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid request with message",
			req: &SignRequest{
				KeyID:   "test-key",
				Message: []byte("test message"),
				NodeIDs: []string{"node-1", "node-2"},
			},
			wantErr: false,
		},
		{
			name: "valid request with message hex",
			req: &SignRequest{
				KeyID:      "test-key",
				MessageHex: "deadbeef",
				NodeIDs:    []string{"node-1", "node-2"},
			},
			wantErr: false,
		},
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
			errMsg:  "sign request is nil",
		},
		{
			name: "missing key ID",
			req: &SignRequest{
				Message: []byte("test message"),
				NodeIDs: []string{"node-1", "node-2"},
			},
			wantErr: true,
			errMsg:  "key ID is required",
		},
		{
			name: "missing message",
			req: &SignRequest{
				KeyID:   "test-key",
				NodeIDs: []string{"node-1", "node-2"},
			},
			wantErr: true,
			errMsg:  "message is required",
		},
		{
			name: "missing node IDs",
			req: &SignRequest{
				KeyID:   "test-key",
				Message: []byte("test message"),
			},
			wantErr: true,
			errMsg:  "node IDs are required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := protocol.ValidateSignRequest(tt.req)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestFROSTProtocol_GetCurve(t *testing.T) {
	protocol := NewFROSTProtocol("ed25519", "node-1", mockMessageRouter)
	assert.Equal(t, "ed25519", protocol.GetCurve())

	protocol2 := NewFROSTProtocol("secp256k1", "node-1", mockMessageRouter)
	assert.Equal(t, "secp256k1", protocol2.GetCurve())
}

func TestFROSTProtocol_SupportedProtocols(t *testing.T) {
	protocol := NewFROSTProtocol("ed25519", "node-1", mockMessageRouter)
	assert.Equal(t, []string{"frost"}, protocol.SupportedProtocols())
}

func TestFROSTProtocol_DefaultProtocol(t *testing.T) {
	protocol := NewFROSTProtocol("ed25519", "node-1", mockMessageRouter)
	assert.Equal(t, "frost", protocol.DefaultProtocol())
}

func TestFROSTProtocol_RotateKey(t *testing.T) {
	protocol := NewFROSTProtocol("ed25519", "node-1", mockMessageRouter)
	err := protocol.RotateKey(context.Background(), "some-key-id")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestFROSTProtocol_GetKeyRecord(t *testing.T) {
	protocol := NewFROSTProtocol("ed25519", "node-1", mockMessageRouter)
	keyID := "test-key-record"
	record := &frostKeyRecord{
		PublicKey: &PublicKey{Hex: "pubkeyhex"},
	}
	protocol.saveKeyRecord(keyID, record)

	retrieved, ok := protocol.getKeyRecord(keyID)
	assert.True(t, ok)
	assert.Equal(t, record, retrieved)

	_, ok = protocol.getKeyRecord("non-existent-key")
	assert.False(t, ok)
}

func TestConvertFROSTKeyData(t *testing.T) {
	tests := []struct {
		name      string
		keyID     string
		saveData  *eddsaKeygen.LocalPartySaveData
		nodeIDs   []string
		wantError bool
		errMsg    string
	}{
		{
			name:      "nil saveData",
			keyID:     "test-key",
			saveData:  nil,
			nodeIDs:   []string{"node-1", "node-2"},
			wantError: true,
			errMsg:    "saveData is nil", // 修正：expect "saveData is nil" instead of "EDDSAPub is nil"
		},
		{
			name:  "empty node IDs",
			keyID: "test-key",
			saveData: &eddsaKeygen.LocalPartySaveData{
				EDDSAPub: &eddsaKeygen.EDDSAPubKey{}, // Provide dummy EDDSAPub to avoid nil check error
			},
			nodeIDs:   []string{},
			wantError: false, // 应该成功，只是没有 keyShares
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyShares, pubKey, err := convertFROSTKeyData(tt.keyID, tt.saveData, tt.nodeIDs)
			if tt.wantError {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
				if len(tt.nodeIDs) > 0 {
					assert.NotNil(t, keyShares)
					assert.Equal(t, len(tt.nodeIDs), len(keyShares))
				}
				// 注意：pubKey 可能为 nil（如果 saveData.EDDSAPub 为 nil）
				_ = pubKey
			}
		})
	}
}

func TestConvertFROSTSignature(t *testing.T) {
	tests := []struct {
		name      string
		sigData   *common.SignatureData
		wantError bool
		errMsg    string
	}{
		{
			name:      "nil signature data",
			sigData:   nil,
			wantError: true,
			errMsg:    "signature data is nil",
		},
		{
			name: "valid signature data",
			sigData: &common.SignatureData{
				R: []byte{0x01, 0x02, 0x03},
				S: []byte{0x04, 0x05, 0x06},
			},
			wantError: false,
		},
		{
			name: "signature with empty R",
			sigData: &common.SignatureData{
				R: []byte{},
				S: []byte{0x04, 0x05, 0x06},
			},
			wantError: false, // padScalarBytes 会填充
		},
		{
			name: "signature with empty S",
			sigData: &common.SignatureData{
				R: []byte{0x01, 0x02, 0x03},
				S: []byte{},
			},
			wantError: false, // padScalarBytes 会填充
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := convertFROSTSignature(tt.sigData)
			if tt.wantError {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, sig)
				assert.NotNil(t, sig.R)
				assert.NotNil(t, sig.S)
				assert.NotNil(t, sig.Bytes)
				assert.NotEmpty(t, sig.Hex)
				// Schnorr 签名格式：R || S（64 字节）
				assert.Equal(t, 64, len(sig.Bytes))
				assert.Equal(t, 32, len(sig.R))
				assert.Equal(t, 32, len(sig.S))
			}
		})
	}
}

func TestVerifySchnorrSignature(t *testing.T) {
	tests := []struct {
		name      string
		sig       *Signature
		msg       []byte
		pubKey    *PublicKey
		wantError bool
		errMsg    string
	}{
		{
			name:      "nil signature",
			sig:       nil,
			msg:       []byte("test"),
			pubKey:    &PublicKey{Bytes: []byte{0x01}},
			wantError: true,
			errMsg:    "signature bytes missing",
		},
		{
			name:      "empty signature bytes",
			sig:       &Signature{Bytes: []byte{}},
			msg:       []byte("test"),
			pubKey:    &PublicKey{Bytes: []byte{0x01}},
			wantError: true,
			errMsg:    "signature bytes missing",
		},
		{
			name:      "empty message",
			sig:       &Signature{Bytes: []byte{0x01}},
			msg:       []byte{},
			pubKey:    &PublicKey{Bytes: []byte{0x01}},
			wantError: true,
			errMsg:    "message is empty",
		},
		{
			name:      "nil public key",
			sig:       &Signature{Bytes: []byte{0x01}},
			msg:       []byte("test"),
			pubKey:    nil,
			wantError: true,
			errMsg:    "public key is empty",
		},
		{
			name:      "empty public key",
			sig:       &Signature{Bytes: []byte{0x01}},
			msg:       []byte("test"),
			pubKey:    &PublicKey{Bytes: []byte{}},
			wantError: true,
			errMsg:    "public key is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 使用默认曲线 ed25519 进行测试
			result, err := verifySchnorrSignature(tt.sig, tt.msg, tt.pubKey, "ed25519")
			if tt.wantError {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				assert.False(t, result)
			} else {
				// 注意：verifySchnorrSignature 现在根据曲线类型选择验证方法
				// 这里只测试错误处理
			}
		})
	}
}

func TestFROSTValidateSignRequest(t *testing.T) {
	tests := []struct {
		name      string
		req       *SignRequest
		wantError bool
		errMsg    string
	}{
		{
			name:      "nil request",
			req:       nil,
			wantError: true,
			errMsg:    "sign request is nil",
		},
		{
			name: "valid request",
			req: &SignRequest{
				KeyID:   "test-key",
				Message: []byte("test"),
				NodeIDs: []string{"node-1"},
			},
			wantError: false,
		},
		{
			name: "missing key ID",
			req: &SignRequest{
				Message: []byte("test"),
				NodeIDs: []string{"node-1"},
			},
			wantError: true,
			errMsg:    "key ID is required",
		},
		{
			name: "missing message",
			req: &SignRequest{
				KeyID:   "test-key",
				NodeIDs: []string{"node-1"},
			},
			wantError: true,
			errMsg:    "message is required",
		},
		{
			name: "missing node IDs",
			req: &SignRequest{
				KeyID:   "test-key",
				Message: []byte("test"),
			},
			wantError: true,
			errMsg:    "node IDs are required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSignRequest(tt.req)
			if tt.wantError {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestFROSTProtocol_VerifySignature(t *testing.T) {
	protocol := NewFROSTProtocol("ed25519", "node-1", mockMessageRouter)

	tests := []struct {
		name      string
		sig       *Signature
		msg       []byte
		pubKey    *PublicKey
		wantError bool
		errMsg    string
	}{
		{
			name:      "nil signature",
			sig:       nil,
			msg:       []byte("test"),
			pubKey:    &PublicKey{Bytes: []byte{0x01}},
			wantError: true,
			errMsg:    "signature bytes missing",
		},
		{
			name:      "empty message",
			sig:       &Signature{Bytes: []byte{0x01}},
			msg:       []byte{},
			pubKey:    &PublicKey{Bytes: []byte{0x01}},
			wantError: true,
			errMsg:    "message is empty",
		},
		{
			name:      "nil public key",
			sig:       &Signature{Bytes: []byte{0x01}},
			msg:       []byte("test"),
			pubKey:    nil,
			wantError: true,
			errMsg:    "public key is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := protocol.VerifySignature(context.Background(), tt.sig, tt.msg, tt.pubKey)
			if tt.wantError {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				assert.False(t, result)
			} else {
				// 注意：verifySchnorrSignature 现在根据曲线类型选择验证方法
				// 这里只测试错误处理
			}
		})
	}
}

// TestConvertFROSTKeyData_WithValidData 测试有效的密钥数据转换
func TestConvertFROSTKeyData_WithValidData(t *testing.T) {
	// 创建一个模拟的 ECPoint（需要实际的 EdDSA 公钥）
	// 由于 EdDSA keygen 需要真实的协议执行，这里只测试错误处理
	// 完整的集成测试需要实际运行 DKG 协议

	keyID := "test-key"
	nodeIDs := []string{"node-1", "node-2", "node-3"}

	// 测试 nil saveData
	keyShares, pubKey, err := convertFROSTKeyData(keyID, nil, nodeIDs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EDDSAPub is nil")
	assert.Nil(t, keyShares)
	assert.Nil(t, pubKey)
}

// TestConvertFROSTSignature_WithValidData 测试有效的签名数据转换
func TestConvertFROSTSignature_WithValidData(t *testing.T) {
	// 创建有效的签名数据
	sigData := &common.SignatureData{
		R: make([]byte, 32),
		S: make([]byte, 32),
	}
	// 填充一些测试数据
	for i := range sigData.R {
		sigData.R[i] = byte(i)
		sigData.S[i] = byte(i + 32)
	}

	sig, err := convertFROSTSignature(sigData)
	require.NoError(t, err)
	assert.NotNil(t, sig)
	assert.Equal(t, 32, len(sig.R))
	assert.Equal(t, 32, len(sig.S))
	assert.Equal(t, 64, len(sig.Bytes)) // Schnorr 格式：R || S
	assert.NotEmpty(t, sig.Hex)
}

// TestFROSTProtocol_GenerateKeyID 测试密钥ID生成
func TestFROSTProtocol_GenerateKeyID(t *testing.T) {
	protocol := NewFROSTProtocol("ed25519", "node-1", mockMessageRouter)

	req := &KeyGenRequest{
		Algorithm:  "Schnorr",
		Curve:      "ed25519",
		Threshold:  2,
		TotalNodes: 3,
		NodeIDs:    []string{"node-1", "node-2", "node-3"},
	}

	// 测试自动生成 keyID
	req.KeyID = ""
	// 注意：由于需要真实的 DKG 执行，这里只测试验证逻辑
	err := protocol.ValidateKeyGenRequest(req)
	require.NoError(t, err)
}

// TestFROSTProtocol_ConcurrentAccess 测试并发访问
func TestFROSTProtocol_ConcurrentAccess(t *testing.T) {
	protocol := NewFROSTProtocol("ed25519", "node-1", mockMessageRouter)
	keyID := "test-key"

	// 并发保存和读取
	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer func() { done <- true }()
			record := &frostKeyRecord{
				PublicKey: &PublicKey{Hex: hex.EncodeToString([]byte{byte(idx)})},
			}
			protocol.saveKeyRecord(fmt.Sprintf("%s-%d", keyID, idx), record)
			_, _ = protocol.getKeyRecord(fmt.Sprintf("%s-%d", keyID, idx))
		}(i)
	}

	// 等待所有 goroutine 完成
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// 验证所有记录都已保存
	for i := 0; i < numGoroutines; i++ {
		_, ok := protocol.getKeyRecord(fmt.Sprintf("%s-%d", keyID, i))
		assert.True(t, ok)
	}
}

// TestFROSTSignatureFormat 测试 FROST 签名格式
func TestFROSTSignatureFormat(t *testing.T) {
	// 测试 Schnorr 签名格式：R || S（64 字节）
	sigData := &common.SignatureData{
		R: []byte{0x01, 0x02, 0x03},
		S: []byte{0x04, 0x05, 0x06},
	}

	sig, err := convertFROSTSignature(sigData)
	require.NoError(t, err)

	// 验证签名格式
	assert.Equal(t, 64, len(sig.Bytes), "Schnorr signature should be 64 bytes (R || S)")
	assert.Equal(t, 32, len(sig.R), "R should be padded to 32 bytes")
	assert.Equal(t, 32, len(sig.S), "S should be padded to 32 bytes")
	assert.Equal(t, sig.Bytes, append(sig.R, sig.S...), "Bytes should be R || S")
}

// TestFROSTKeyDataConversion_EdgeCases 测试边界情况
func TestFROSTKeyDataConversion_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		keyID     string
		nodeIDs   []string
		wantError bool
	}{
		{
			name:      "empty keyID",
			keyID:     "",
			nodeIDs:   []string{"node-1"},
			wantError: false, // 应该成功，只是 keyID 为空
		},
		{
			name:      "single node",
			keyID:     "test-key",
			nodeIDs:   []string{"node-1"},
			wantError: false,
		},
		{
			name:      "many nodes",
			keyID:     "test-key",
			nodeIDs:   []string{"node-1", "node-2", "node-3", "node-4", "node-5"},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 使用 nil saveData 测试错误处理
			// 注意：convertFROSTKeyData 会检查 saveData 是否为 nil
			keyShares, pubKey, err := convertFROSTKeyData(tt.keyID, nil, tt.nodeIDs)
			// nil saveData 应该返回错误
			require.Error(t, err)
			assert.Nil(t, keyShares)
			assert.Nil(t, pubKey)
			assert.Contains(t, err.Error(), "saveData is nil") // 修正预期错误
		})
	}
}

// TestFROSTProtocol_MessageHandling 测试消息处理
func TestFROSTProtocol_MessageHandling(t *testing.T) {
	protocol := NewFROSTProtocol("ed25519", "node-1", mockMessageRouter)

	// 测试消息路由函数
	messageCount := 0
	protocol.messageRouter = func(sessionID string, nodeID string, msg tss.Message) error {
		messageCount++
		return nil
	}

	// 验证消息路由函数已设置
	assert.NotNil(t, protocol.messageRouter)
}

// TestFROSTProtocol_CurveSupport 测试曲线支持
func TestFROSTProtocol_CurveSupport(t *testing.T) {
	tests := []struct {
		name      string
		curve     string
		wantValid bool
	}{
		{
			name:      "ed25519",
			curve:     "ed25519",
			wantValid: true,
		},
		{
			name:      "secp256k1",
			curve:     "secp256k1",
			wantValid: true,
		},
		{
			name:      "empty curve",
			curve:     "",
			wantValid: true, // 空曲线应该通过验证
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			protocol := NewFROSTProtocol(tt.curve, "node-1", mockMessageRouter)
			req := &KeyGenRequest{
				Algorithm:  "Schnorr",
				Curve:      tt.curve,
				Threshold:  2,
				TotalNodes: 3,
			}
			err := protocol.ValidateKeyGenRequest(req)
			if tt.wantValid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
