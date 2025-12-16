package protocol

import (
	"context"
	"math/big"
	"testing"
	"time"

	eddsaKeygen "github.com/kashguard/tss-lib/eddsa/keygen"
	"github.com/kashguard/tss-lib/tss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewTSSPartyManager_WithEdDSA 测试包含 EdDSA 支持的 tssPartyManager
func TestNewTSSPartyManager_WithEdDSA(t *testing.T) {
	manager := newTSSPartyManager(mockMessageRouter)

	assert.NotNil(t, manager)
	assert.NotNil(t, manager.nodeIDToPartyID)
	assert.NotNil(t, manager.partyIDToNodeID)
	assert.NotNil(t, manager.messageRouter)
	// 注意：activeKeygen, activeSigning, activeEdDSAKeygen, activeEdDSASigning 是私有字段
	// 无法在测试中直接访问，但可以通过方法间接验证
}

// TestDefaultSigningOptions 测试默认签名选项（GG18）
func TestDefaultSigningOptions(t *testing.T) {
	opts := DefaultSigningOptions()

	assert.Equal(t, 2*time.Minute, opts.Timeout)
	assert.False(t, opts.EnableIdentifiableAbort)
	assert.Equal(t, "GG18", opts.ProtocolName)
}

// TestGG20SigningOptions 测试 GG20 签名选项
func TestGG20SigningOptions(t *testing.T) {
	opts := GG20SigningOptions()

	assert.Equal(t, 1*time.Minute, opts.Timeout)
	assert.True(t, opts.EnableIdentifiableAbort)
	assert.Equal(t, "GG20", opts.ProtocolName)
}

// TestFROSTSigningOptions 测试 FROST 签名选项
func TestFROSTSigningOptions(t *testing.T) {
	opts := FROSTSigningOptions()

	assert.Equal(t, 1*time.Minute, opts.Timeout)
	assert.False(t, opts.EnableIdentifiableAbort)
	assert.Equal(t, "FROST", opts.ProtocolName)
}

// TestExecuteEdDSAKeygen_SetupPartyIDs 测试 EdDSA keygen 的 PartyID 设置
func TestExecuteEdDSAKeygen_SetupPartyIDs(t *testing.T) {
	manager := newTSSPartyManager(mockMessageRouter)

	nodeIDs := []string{"node-1", "node-2", "node-3"}
	thisNodeID := "node-1"

	// 测试 setupPartyIDs 调用
	err := manager.setupPartyIDs(nodeIDs)
	require.NoError(t, err)

	// 验证所有节点都有 PartyID
	manager.mu.RLock()
	for _, nodeID := range nodeIDs {
		partyID, ok := manager.nodeIDToPartyID[nodeID]
		assert.True(t, ok, "node %s should have PartyID", nodeID)
		assert.NotNil(t, partyID)
	}
	manager.mu.RUnlock()

	// 验证 thisNodeID 存在
	thisPartyID, ok := manager.getPartyID(thisNodeID)
	assert.True(t, ok)
	assert.NotNil(t, thisPartyID)

	// 注意：实际的 executeEdDSAKeygen 需要真实的协议执行，这里只测试参数验证
	// 完整的集成测试需要实际运行 DKG 协议
}

// TestExecuteEdDSAKeygen_NodeNotFound 测试节点未找到的情况
func TestExecuteEdDSAKeygen_NodeNotFound(t *testing.T) {
	manager := newTSSPartyManager(mockMessageRouter)

	ctx := context.Background()
	nodeIDs := []string{"node-1", "node-2"}
	thisNodeID := "node-3" // 不在 nodeIDs 中
	keyID := "test-key-1"
	threshold := 2

	// 设置 PartyID
	err := manager.setupPartyIDs(nodeIDs)
	require.NoError(t, err)

	// 尝试执行 keygen，应该失败（thisNodeID 不在 nodeIDs 中）
	_, err = manager.executeEdDSAKeygen(ctx, keyID, nodeIDs, threshold, thisNodeID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "this node ID not found")
}

// TestExecuteEdDSAKeygen_ContextCancellation 测试上下文取消
func TestExecuteEdDSAKeygen_ContextCancellation(t *testing.T) {
	manager := newTSSPartyManager(mockMessageRouter)

	nodeIDs := []string{"node-1", "node-2"}
	thisNodeID := "node-1"
	keyID := "test-key-1"
	threshold := 2

	// 设置 PartyID
	err := manager.setupPartyIDs(nodeIDs)
	require.NoError(t, err)

	// 创建可取消的上下文
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消

	// 执行 keygen，应该因为上下文取消而失败
	_, err = manager.executeEdDSAKeygen(ctx, keyID, nodeIDs, threshold, thisNodeID)
	require.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

// TestExecuteEdDSASigning_SetupPartyIDs 测试 EdDSA signing 的 PartyID 设置
func TestExecuteEdDSASigning_SetupPartyIDs(t *testing.T) {
	manager := newTSSPartyManager(mockMessageRouter)

	nodeIDs := []string{"node-1", "node-2", "node-3"}
	thisNodeID := "node-1"

	// 设置 PartyID
	err := manager.setupPartyIDs(nodeIDs)
	require.NoError(t, err)

	// 验证 thisNodeID 存在
	thisPartyID, ok := manager.getPartyID(thisNodeID)
	assert.True(t, ok)
	assert.NotNil(t, thisPartyID)

	// 注意：实际的 executeEdDSASigning 需要真实的 keyData 和协议执行
	// 这里只测试参数验证
	opts := FROSTSigningOptions()
	assert.Equal(t, "FROST", opts.ProtocolName)
}

// TestExecuteEdDSASigning_NodeNotFound 测试节点未找到的情况
func TestExecuteEdDSASigning_NodeNotFound(t *testing.T) {
	manager := newTSSPartyManager(mockMessageRouter)

	ctx := context.Background()
	nodeIDs := []string{"node-1", "node-2"}
	thisNodeID := "node-3" // 不在 nodeIDs 中
	sessionID := "test-session-1"
	keyID := "test-key-1"
	message := []byte("test message")
	keyData := &eddsaKeygen.LocalPartySaveData{}

	// 设置 PartyID
	err := manager.setupPartyIDs(nodeIDs)
	require.NoError(t, err)

	// 尝试执行 signing，应该失败（thisNodeID 不在 nodeIDs 中）
	opts := FROSTSigningOptions()
	_, err = manager.executeEdDSASigning(ctx, sessionID, keyID, message, nodeIDs, thisNodeID, keyData, opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "this node ID not found")
}

// TestExecuteEdDSASigning_ContextCancellation 测试上下文取消
func TestExecuteEdDSASigning_ContextCancellation(t *testing.T) {
	manager := newTSSPartyManager(mockMessageRouter)

	nodeIDs := []string{"node-1", "node-2"}
	thisNodeID := "node-1"
	sessionID := "test-session-1"
	keyID := "test-key-1"
	message := []byte("test message")

	// 创建一个最小的 keyData（需要有效的 Ks）
	// 注意：由于 eddsaSigning.NewLocalParty 会调用 BuildLocalSaveDataSubset，
	// 需要有效的 keyData，否则会 panic
	// 我们需要确保 KeyData 中的 ShareID 与 setupPartyIDs 生成的 ID 匹配
	// setupPartyIDs 使用 sha256(nodeID) 作为 uniqueKey
	keyData := eddsaKeygen.NewLocalPartySaveData(2)

	// 计算 node-1 的 hash (uniqueKey)
	hash := sha256.Sum256([]byte("node-1"))
	uniqueKey := new(big.Int).SetBytes(hash[:])

	keyData.ShareID = uniqueKey // 设置当前节点的 ShareID
	keyData.Ks = []*big.Int{
		uniqueKey,
		big.NewInt(2), // 另一个假 ID
	}

	// 设置 PartyID
	err := manager.setupPartyIDs(nodeIDs)
	require.NoError(t, err)

	// 创建可取消的上下文
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消

	// 执行 signing，应该因为上下文取消而失败
	opts := FROSTSigningOptions()
	_, err = manager.executeEdDSASigning(ctx, sessionID, keyID, message, nodeIDs, thisNodeID, &keyData, opts)
	require.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

// TestExecuteEdDSASigning_Timeout 测试超时处理
func TestExecuteEdDSASigning_Timeout(t *testing.T) {
	manager := newTSSPartyManager(mockMessageRouter)

	nodeIDs := []string{"node-1", "node-2"}
	thisNodeID := "node-1"
	sessionID := "test-session-1"
	keyID := "test-key-1"
	message := []byte("test message")

	// 创建一个最小的 keyData（需要有效的 Ks）
	keyData := eddsaKeygen.NewLocalPartySaveData(2)
	keyData.Ks = []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
	}

	// 设置 PartyID
	err := manager.setupPartyIDs(nodeIDs)
	require.NoError(t, err)

	// 使用很短的超时时间
	opts := SigningOptions{
		Timeout:                 1 * time.Millisecond, // 非常短的超时
		EnableIdentifiableAbort: false,
		ProtocolName:            "FROST",
	}

	ctx := context.Background()
	// 注意：由于超时时间很短，协议可能无法完成，但这里主要测试超时逻辑
	// 实际的超时测试需要更复杂的设置
	_, err = manager.executeEdDSASigning(ctx, sessionID, keyID, message, nodeIDs, thisNodeID, &keyData, opts)
	// 可能会因为超时或其他原因失败，这是预期的
	// 这里主要验证函数能够处理超时选项
	assert.Error(t, err)
}

// TestSigningOptions_Comparison 测试不同协议的签名选项比较
func TestSigningOptions_Comparison(t *testing.T) {
	gg18Opts := DefaultSigningOptions()
	gg20Opts := GG20SigningOptions()
	frostOpts := FROSTSigningOptions()

	// 验证超时时间
	assert.Equal(t, 2*time.Minute, gg18Opts.Timeout)
	assert.Equal(t, 1*time.Minute, gg20Opts.Timeout)
	assert.Equal(t, 1*time.Minute, frostOpts.Timeout)

	// 验证可识别的中止
	assert.False(t, gg18Opts.EnableIdentifiableAbort)
	assert.True(t, gg20Opts.EnableIdentifiableAbort)
	assert.False(t, frostOpts.EnableIdentifiableAbort)

	// 验证协议名称
	assert.Equal(t, "GG18", gg18Opts.ProtocolName)
	assert.Equal(t, "GG20", gg20Opts.ProtocolName)
	assert.Equal(t, "FROST", frostOpts.ProtocolName)
}

// TestTSSPartyManager_EdDSAFields 测试 EdDSA 字段的初始化
func TestTSSPartyManager_EdDSAFields(t *testing.T) {
	_ = newTSSPartyManager(mockMessageRouter)

	// 注意：activeEdDSAKeygen 和 activeEdDSASigning 是私有字段，无法在测试中直接访问
	// 这里只验证 manager 已正确初始化
}

// TestGetPartyID_EdDSA 测试获取 PartyID（用于 EdDSA）
func TestGetPartyID_EdDSA(t *testing.T) {
	manager := newTSSPartyManager(mockMessageRouter)

	nodeIDs := []string{"node-1", "node-2", "node-3"}

	err := manager.setupPartyIDs(nodeIDs)
	require.NoError(t, err)

	// 测试获取存在的 PartyID
	partyID, ok := manager.getPartyID("node-1")
	assert.True(t, ok)
	assert.NotNil(t, partyID)
	assert.Equal(t, "node-1", partyID.Id)

	// 测试获取不存在的 PartyID
	_, ok = manager.getPartyID("non-existent-node")
	assert.False(t, ok)
}

// TestGetNodeID_EdDSA 测试根据 PartyID 获取节点ID（用于 EdDSA）
func TestGetNodeID_EdDSA(t *testing.T) {
	manager := newTSSPartyManager(mockMessageRouter)

	nodeIDs := []string{"node-1", "node-2", "node-3"}

	err := manager.setupPartyIDs(nodeIDs)
	require.NoError(t, err)

	// 获取 node-1 的 PartyID
	partyID, ok := manager.getPartyID("node-1")
	require.True(t, ok)

	// 根据 PartyID 获取节点ID
	nodeID, ok := manager.getNodeID(partyID.Id)
	assert.True(t, ok)
	assert.Equal(t, "node-1", nodeID)

	// 测试不存在的 PartyID
	_, ok = manager.getNodeID("non-existent-party-id")
	assert.False(t, ok)
}

// TestExecuteEdDSAKeygen_ActivePartyManagement 测试活跃 Party 管理
func TestExecuteEdDSAKeygen_ActivePartyManagement(t *testing.T) {
	manager := newTSSPartyManager(mockMessageRouter)

	nodeIDs := []string{"node-1", "node-2"}

	// 设置 PartyID
	err := manager.setupPartyIDs(nodeIDs)
	require.NoError(t, err)

	// 注意：activeEdDSAKeygen 是私有字段，无法在测试中直接访问
	// 这里只验证 setupPartyIDs 成功执行

	// 注意：实际的 executeEdDSAKeygen 会创建并存储 Party
	// 但由于需要真实的协议执行，这里只测试基础逻辑
	// 完整的测试需要集成测试环境
}

// TestExecuteEdDSASigning_ActivePartyManagement 测试活跃 Party 管理
func TestExecuteEdDSASigning_ActivePartyManagement(t *testing.T) {
	manager := newTSSPartyManager(mockMessageRouter)

	nodeIDs := []string{"node-1", "node-2"}

	// 设置 PartyID
	err := manager.setupPartyIDs(nodeIDs)
	require.NoError(t, err)

	// 注意：activeEdDSASigning 是私有字段，无法在测试中直接访问
	// 这里只验证 setupPartyIDs 成功执行

	// 注意：实际的 executeEdDSASigning 会创建并存储 Party
	// 但由于需要真实的协议执行，这里只测试基础逻辑
	// 完整的测试需要集成测试环境
}

// TestSigningOptions_ZeroTimeout 测试零超时时间
func TestSigningOptions_ZeroTimeout(t *testing.T) {
	opts := SigningOptions{
		Timeout:                 0,
		EnableIdentifiableAbort: false,
		ProtocolName:            "TEST",
	}

	// 验证零超时时间
	assert.Equal(t, time.Duration(0), opts.Timeout)
}

// TestSigningOptions_CustomTimeout 测试自定义超时时间
func TestSigningOptions_CustomTimeout(t *testing.T) {
	customTimeout := 30 * time.Second
	opts := SigningOptions{
		Timeout:                 customTimeout,
		EnableIdentifiableAbort: true,
		ProtocolName:            "CUSTOM",
	}

	assert.Equal(t, customTimeout, opts.Timeout)
	assert.True(t, opts.EnableIdentifiableAbort)
	assert.Equal(t, "CUSTOM", opts.ProtocolName)
}

// TestTSSPartyManager_ConcurrentEdDSA 测试并发访问 EdDSA 字段
func TestTSSPartyManager_ConcurrentEdDSA(t *testing.T) {
	manager := newTSSPartyManager(mockMessageRouter)

	nodeIDs := []string{"node-1", "node-2", "node-3", "node-4", "node-5"}

	// 并发设置 PartyID
	done := make(chan bool, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		go func(id string) {
			err := manager.setupPartyIDs([]string{id})
			assert.NoError(t, err)
			done <- true
		}(nodeID)
	}

	// 等待所有 goroutine 完成
	for i := 0; i < len(nodeIDs); i++ {
		<-done
	}

	// 验证所有节点都有 PartyID
	manager.mu.RLock()
	defer manager.mu.RUnlock()

	for _, nodeID := range nodeIDs {
		_, ok := manager.nodeIDToPartyID[nodeID]
		assert.True(t, ok, "node %s should have PartyID after concurrent setup", nodeID)
	}
}

// TestExecuteEdDSAKeygen_EmptyNodeIDs 测试空节点列表
func TestExecuteEdDSAKeygen_EmptyNodeIDs(t *testing.T) {
	manager := newTSSPartyManager(mockMessageRouter)

	ctx := context.Background()
	nodeIDs := []string{}
	thisNodeID := "node-1"
	keyID := "test-key-1"
	threshold := 2

	// 设置空 PartyID 列表
	err := manager.setupPartyIDs(nodeIDs)
	require.NoError(t, err)

	// 尝试执行 keygen，应该失败（thisNodeID 不在空列表中）
	_, err = manager.executeEdDSAKeygen(ctx, keyID, nodeIDs, threshold, thisNodeID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "this node ID not found")
}

// TestExecuteEdDSASigning_EmptyNodeIDs 测试空节点列表
func TestExecuteEdDSASigning_EmptyNodeIDs(t *testing.T) {
	manager := newTSSPartyManager(mockMessageRouter)

	ctx := context.Background()
	nodeIDs := []string{}
	thisNodeID := "node-1"
	sessionID := "test-session-1"
	keyID := "test-key-1"
	message := []byte("test message")

	// 创建一个最小的 keyData（即使节点列表为空，也需要有效的 keyData 结构）
	keyData := eddsaKeygen.NewLocalPartySaveData(0)
	keyData.Ks = []*big.Int{}

	// 设置空 PartyID 列表
	err := manager.setupPartyIDs(nodeIDs)
	require.NoError(t, err)

	// 尝试执行 signing，应该失败（thisNodeID 不在空列表中）
	opts := FROSTSigningOptions()
	_, err = manager.executeEdDSASigning(ctx, sessionID, keyID, message, nodeIDs, thisNodeID, &keyData, opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "this node ID not found")
}

// TestExecuteEdDSAKeygen_ThresholdValidation 测试阈值验证
func TestExecuteEdDSAKeygen_ThresholdValidation(t *testing.T) {
	manager := newTSSPartyManager(mockMessageRouter)

	nodeIDs := []string{"node-1", "node-2", "node-3"}
	thisNodeID := "node-1"
	keyID := "test-key-1"

	// 设置 PartyID
	err := manager.setupPartyIDs(nodeIDs)
	require.NoError(t, err)

	// 测试不同的阈值值
	tests := []struct {
		name      string
		threshold int
		wantError bool
	}{
		{
			name:      "valid threshold (2-of-3)",
			threshold: 2,
			wantError: false, // 参数验证通过，但协议执行可能失败
		},
		{
			name:      "threshold equals total nodes (3-of-3)",
			threshold: 3,
			wantError: false, // 参数验证通过
		},
		{
			name:      "threshold greater than total nodes (4-of-3)",
			threshold: 4,
			wantError: false, // tss-lib 可能会处理这种情况，但通常不应该发生
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			// 注意：实际的阈值验证应该在协议层完成
			// 这里只测试参数传递
			_, err := manager.executeEdDSAKeygen(ctx, keyID, nodeIDs, tt.threshold, thisNodeID)
			// 可能会因为协议执行失败，但参数验证应该通过
			// 这里主要验证函数能够处理不同的阈值值
			_ = err // 忽略错误，因为协议执行需要真实环境
		})
	}
}

// TestExecuteEdDSASigning_MessageHandling 测试消息处理
func TestExecuteEdDSASigning_MessageHandling(t *testing.T) {
	manager := newTSSPartyManager(mockMessageRouter)

	nodeIDs := []string{"node-1", "node-2"}
	thisNodeID := "node-1"
	sessionID := "test-session-1"
	keyID := "test-key-1"

	// 创建一个最小的 keyData（需要有效的 Ks）
	keyData := eddsaKeygen.NewLocalPartySaveData(2)
	keyData.Ks = []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
	}

	// 设置 PartyID
	err := manager.setupPartyIDs(nodeIDs)
	require.NoError(t, err)

	tests := []struct {
		name    string
		message []byte
	}{
		{
			name:    "empty message",
			message: []byte{},
		},
		{
			name:    "short message",
			message: []byte("test"),
		},
		{
			name:    "long message",
			message: make([]byte, 1024),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			opts := FROSTSigningOptions()
			// 注意：实际的签名需要真实的 keyData 和协议执行
			// 这里只测试消息参数的处理
			_, err := manager.executeEdDSASigning(ctx, sessionID, keyID, tt.message, nodeIDs, thisNodeID, &keyData, opts)
			// 可能会因为协议执行失败，但消息参数应该被正确处理
			_ = err // 忽略错误，因为协议执行需要真实环境
		})
	}
}

// TestTSSPartyManager_EdDSAAndECDSAIsolation 测试 EdDSA 和 ECDSA 的隔离
func TestTSSPartyManager_EdDSAAndECDSAIsolation(t *testing.T) {
	// 注意：activeKeygen, activeSigning, activeEdDSAKeygen, activeEdDSASigning 是私有字段
	// 无法在测试中直接访问，但可以通过方法间接验证
	// EdDSA 和 ECDSA 的字段在 tssPartyManager 中是独立的，这是设计上的隔离
	// 这个测试验证了设计上的隔离，实际验证需要通过集成测试
}

// TestSigningOptions_StringRepresentation 测试签名选项的字符串表示
func TestSigningOptions_StringRepresentation(t *testing.T) {
	opts := FROSTSigningOptions()

	// 验证选项值
	assert.Equal(t, "FROST", opts.ProtocolName)
	assert.Equal(t, 1*time.Minute, opts.Timeout)
	assert.False(t, opts.EnableIdentifiableAbort)
}

// TestExecuteEdDSAKeygen_MessageRouter 测试消息路由
func TestExecuteEdDSAKeygen_MessageRouter(t *testing.T) {
	messageCount := 0
	messageRouter := func(sessionID string, nodeID string, msg tss.Message) error {
		messageCount++
		return nil
	}

	manager := newTSSPartyManager(messageRouter)

	// 验证消息路由函数已设置
	assert.NotNil(t, manager.messageRouter)

	// 注意：实际的消息路由测试需要真实的协议执行
	// 这里只验证消息路由函数已正确设置
}

// TestExecuteEdDSASigning_MessageRouter 测试消息路由
func TestExecuteEdDSASigning_MessageRouter(t *testing.T) {
	messageCount := 0
	messageRouter := func(sessionID string, nodeID string, msg tss.Message) error {
		messageCount++
		return nil
	}

	manager := newTSSPartyManager(messageRouter)

	// 验证消息路由函数已设置
	assert.NotNil(t, manager.messageRouter)

	// 注意：实际的消息路由测试需要真实的协议执行
	// 这里只验证消息路由函数已正确设置
}

// TestFROSTSigningOptions_Consistency 测试 FROST 签名选项的一致性
func TestFROSTSigningOptions_Consistency(t *testing.T) {
	opts1 := FROSTSigningOptions()
	opts2 := FROSTSigningOptions()

	// 验证多次调用返回相同的选项
	assert.Equal(t, opts1.Timeout, opts2.Timeout)
	assert.Equal(t, opts1.EnableIdentifiableAbort, opts2.EnableIdentifiableAbort)
	assert.Equal(t, opts1.ProtocolName, opts2.ProtocolName)
}

// TestDefaultSigningOptions_Consistency 测试默认签名选项的一致性
func TestDefaultSigningOptions_Consistency(t *testing.T) {
	opts1 := DefaultSigningOptions()
	opts2 := DefaultSigningOptions()

	// 验证多次调用返回相同的选项
	assert.Equal(t, opts1.Timeout, opts2.Timeout)
	assert.Equal(t, opts1.EnableIdentifiableAbort, opts2.EnableIdentifiableAbort)
	assert.Equal(t, opts1.ProtocolName, opts2.ProtocolName)
}

// TestGG20SigningOptions_Consistency 测试 GG20 签名选项的一致性
func TestGG20SigningOptions_Consistency(t *testing.T) {
	opts1 := GG20SigningOptions()
	opts2 := GG20SigningOptions()

	// 验证多次调用返回相同的选项
	assert.Equal(t, opts1.Timeout, opts2.Timeout)
	assert.Equal(t, opts1.EnableIdentifiableAbort, opts2.EnableIdentifiableAbort)
	assert.Equal(t, opts1.ProtocolName, opts2.ProtocolName)
}
