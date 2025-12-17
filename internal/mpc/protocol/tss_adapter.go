package protocol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kashguard/tss-lib/common"
	"github.com/kashguard/tss-lib/ecdsa/keygen"
	"github.com/kashguard/tss-lib/ecdsa/resharing"
	"github.com/kashguard/tss-lib/ecdsa/signing"
	eddsaKeygen "github.com/kashguard/tss-lib/eddsa/keygen"
	eddsaSigning "github.com/kashguard/tss-lib/eddsa/signing"
	"github.com/kashguard/tss-lib/tss"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// TSSSigningOptions 签名选项
type TSSSigningOptions struct {
	Timeout                 time.Duration
	EnableIdentifiableAbort bool
	ProtocolName            string
}

// DefaultSigningOptions 返回默认签名选项
func DefaultSigningOptions() TSSSigningOptions {
	return TSSSigningOptions{
		Timeout:                 10 * time.Minute,
		EnableIdentifiableAbort: true,
		ProtocolName:            "TSS",
	}
}

// FROSTSigningOptions 返回 FROST 的签名选项
func FROSTSigningOptions() TSSSigningOptions {
	return TSSSigningOptions{
		Timeout:                 5 * time.Minute,
		EnableIdentifiableAbort: false,
		ProtocolName:            "FROST",
	}
}

// tssPartyManager 管理 tss-lib 的 Party 实例和消息路由（通用适配层，供 GG18/GG20/FROST 使用）
type tssPartyManager struct {
	mu sync.RWMutex

	// 节点到 PartyID 的映射
	nodeIDToPartyID map[string]*tss.PartyID
	partyIDToNodeID map[string]string

	// 当前活跃的协议实例（ECDSA - GG18/GG20）
	activeKeygen    map[string]*keygen.LocalParty
	activeSigning   map[string]*signing.LocalParty
	activeResharing map[string]*resharing.LocalParty

	// 当前活跃的协议实例（EdDSA - FROST）
	activeEdDSAKeygen  map[string]*eddsaKeygen.LocalParty
	activeEdDSASigning map[string]*eddsaSigning.LocalParty

	// 消息路由：从 tss-lib 消息到节点通信
	// 参数：sessionID（用于DKG或签名会话），nodeID（目标节点），msg（tss-lib消息）
	messageRouter func(sessionID string, nodeID string, msg tss.Message, isBroadcast bool) error

	// 接收到的消息队列（用于处理来自其他节点的消息）
	// 消息包含字节数据和发送方节点ID
	incomingKeygenMessages    map[string]chan *incomingMessage
	incomingSigningMessages   map[string]chan *incomingMessage
	incomingResharingMessages map[string]chan *incomingMessage

	// 会话ID映射：keyID/sessionID -> sessionID（用于消息路由时获取会话ID）
	sessionIDMap map[string]string

	// 会话创建时间（用于清理过期会话）
	sessionCreationTimes map[string]time.Time

	// 会话清理定时器
	cleanupTicker *time.Ticker
	cleanupDone   chan struct{}
}

// incomingMessage 接收到的消息（包含消息字节和发送方信息）
type incomingMessage struct {
	msgBytes    []byte
	fromNodeID  string
	isBroadcast bool
}

func newTSSPartyManager(messageRouter func(sessionID string, nodeID string, msg tss.Message, isBroadcast bool) error) *tssPartyManager {
	manager := &tssPartyManager{
		nodeIDToPartyID:           make(map[string]*tss.PartyID),
		partyIDToNodeID:           make(map[string]string),
		activeKeygen:              make(map[string]*keygen.LocalParty),
		activeSigning:             make(map[string]*signing.LocalParty),
		activeResharing:           make(map[string]*resharing.LocalParty),
		activeEdDSAKeygen:         make(map[string]*eddsaKeygen.LocalParty),
		activeEdDSASigning:        make(map[string]*eddsaSigning.LocalParty),
		messageRouter:             messageRouter,
		incomingKeygenMessages:    make(map[string]chan *incomingMessage),
		incomingSigningMessages:   make(map[string]chan *incomingMessage),
		incomingResharingMessages: make(map[string]chan *incomingMessage),
		sessionIDMap:              make(map[string]string),
		sessionCreationTimes:      make(map[string]time.Time),
		cleanupDone:               make(chan struct{}),
	}
	// 启动会话清理器
	manager.startSessionCleaner()
	return manager
}

// startSessionCleaner 启动会话清理器
func (m *tssPartyManager) startSessionCleaner() {
	m.cleanupTicker = time.NewTicker(5 * time.Minute)
	go func() {
		for {
			select {
			case <-m.cleanupTicker.C:
				m.cleanupStaleSessions()
			case <-m.cleanupDone:
				return
			}
		}
	}()
}

// cleanupStaleSessions 清理过期会话
func (m *tssPartyManager) cleanupStaleSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	timeout := 30 * time.Minute // 默认30分钟超时

	for sessionID, createTime := range m.sessionCreationTimes {
		if now.Sub(createTime) > timeout {
			log.Info().Str("session_id", sessionID).Msg("Cleaning up stale session")

			// 清理各类资源
			delete(m.activeKeygen, sessionID)
			delete(m.activeSigning, sessionID)
			delete(m.activeResharing, sessionID)
			delete(m.activeEdDSAKeygen, sessionID)
			delete(m.activeEdDSASigning, sessionID)
			delete(m.sessionIDMap, sessionID)

			// 关闭并清理通道
			if ch, ok := m.incomingKeygenMessages[sessionID]; ok {
				close(ch)
				delete(m.incomingKeygenMessages, sessionID)
			}
			if ch, ok := m.incomingSigningMessages[sessionID]; ok {
				close(ch)
				delete(m.incomingSigningMessages, sessionID)
			}
			if ch, ok := m.incomingResharingMessages[sessionID]; ok {
				close(ch)
				delete(m.incomingResharingMessages, sessionID)
			}

			delete(m.sessionCreationTimes, sessionID)
		}
	}
}

// setupPartyIDs 为节点创建 PartyID
func (m *tssPartyManager) setupPartyIDs(nodeIDs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, nodeID := range nodeIDs {
		if _, exists := m.nodeIDToPartyID[nodeID]; exists {
			continue
		}

		// 使用节点ID的哈希作为唯一密钥
		hash := sha256.Sum256([]byte(nodeID))
		uniqueKey := new(big.Int).SetBytes(hash[:])

		partyID := tss.NewPartyID(nodeID, nodeID, uniqueKey)
		m.nodeIDToPartyID[nodeID] = partyID
		m.partyIDToNodeID[partyID.Id] = nodeID
	}

	log.Debug().
		Strs("node_ids", nodeIDs).
		Int("mapping_size", len(m.nodeIDToPartyID)).
		Msg("PartyID mapping prepared")

	return nil
}

// getPartyIDs 获取排序后的 PartyID 列表
func (m *tssPartyManager) getPartyIDs(nodeIDs []string) (tss.SortedPartyIDs, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	parties := make([]*tss.PartyID, 0, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		partyID, ok := m.nodeIDToPartyID[nodeID]
		if !ok {
			// 添加更多调试信息
			availableNodeIDs := make([]string, 0, len(m.nodeIDToPartyID))
			for nid := range m.nodeIDToPartyID {
				availableNodeIDs = append(availableNodeIDs, nid)
			}
			return nil, errors.Errorf("party ID not found for node: %s (available nodeIDs: %v, requested nodeIDs: %v)", nodeID, availableNodeIDs, nodeIDs)
		}
		parties = append(parties, partyID)
	}

	return tss.SortPartyIDs(parties), nil
}

// getPartyID 获取指定节点的 PartyID（用于外部访问）
func (m *tssPartyManager) getPartyID(nodeID string) (*tss.PartyID, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	partyID, ok := m.nodeIDToPartyID[nodeID]
	return partyID, ok
}

// getNodeID 根据 PartyID 获取节点ID（用于外部访问）
func (m *tssPartyManager) getNodeID(partyID string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	nodeID, ok := m.partyIDToNodeID[partyID]
	return nodeID, ok
}

// executeKeygen 执行真正的 DKG 协议
func (m *tssPartyManager) executeKeygen(
	ctx context.Context,
	keyID string,
	nodeIDs []string,
	threshold int,
	thisNodeID string,
) (*keygen.LocalPartySaveData, error) {
	var outMessageCount int64
	var processedMessageCount int64
	var lastMessageTime atomic.Int64
	lastMessageTime.Store(time.Now().UnixNano())
	// 注意：sync.Once应该已经防止了重复启动，所以这里不需要检查activeKeygen
	// 但如果sync.Once失效，这里会创建一个新实例，导致消息混乱
	// 为了安全，我们仍然检查一下，但只记录警告
	m.mu.RLock()
	_, exists := m.activeKeygen[keyID]
	m.mu.RUnlock()

	if exists {
		log.Error().
			Str("key_id", keyID).
			Str("this_node_id", thisNodeID).
			Msg("CRITICAL: DKG instance already exists but executeKeygen was called again - sync.Once may have failed")
		// 返回错误，防止创建重复实例
		return nil, errors.Errorf("DKG instance already exists for keyID %s (sync.Once should have prevented this)", keyID)
	}

	// 确保节点列表有序，避免 PartyID 映射不一致
	sortedNodeIDs := make([]string, len(nodeIDs))
	copy(sortedNodeIDs, nodeIDs)
	sort.Strings(sortedNodeIDs)

	if err := m.setupPartyIDs(sortedNodeIDs); err != nil {
		return nil, errors.Wrap(err, "setup party IDs")
	}

	parties, err := m.getPartyIDs(sortedNodeIDs)
	if err != nil {
		return nil, errors.Wrap(err, "get party IDs")
	}

	log.Info().
		Str("key_id", keyID).
		Strs("node_ids_sorted", sortedNodeIDs).
		Int("party_count", len(parties)).
		Int("threshold", threshold).
		Msg("Starting TSS keygen with sorted node list")

	thisPartyID, ok := m.nodeIDToPartyID[thisNodeID]
	if !ok {
		return nil, errors.Errorf("this node ID not found: %s", thisNodeID)
	}

	ctxTSS := tss.NewPeerContext(parties)
	params := tss.NewParameters(tss.S256(), ctxTSS, thisPartyID, len(parties), threshold)

	// 创建消息通道
	outCh := make(chan tss.Message, len(parties))
	endCh := make(chan *keygen.LocalPartySaveData, 1)
	errCh := make(chan *tss.Error, 1)

	// 创建 LocalParty
	party := keygen.NewLocalParty(params, outCh, endCh)

	m.mu.Lock()
	// 类型断言为 *keygen.LocalParty
	if localParty, ok := party.(*keygen.LocalParty); ok {
		m.activeKeygen[keyID] = localParty
	}
	// 记录会话ID映射（keyID作为sessionID）
	m.sessionIDMap[keyID] = keyID
	m.sessionCreationTimes[keyID] = time.Now()
	m.mu.Unlock()

	// 创建消息队列（如果不存在）
	m.mu.Lock()
	msgCh, exists := m.incomingKeygenMessages[keyID]
	if !exists {
		msgCh = make(chan *incomingMessage, 100)
		m.incomingKeygenMessages[keyID] = msgCh
		log.Info().
			Str("key_id", keyID).
			Msg("Created incomingKeygenMessages channel for DKG")
	} else {
		log.Info().
			Str("key_id", keyID).
			Str("msg_ch_ptr", fmt.Sprintf("%p", msgCh)).
			Int("msg_ch_len", len(msgCh)).
			Msg("Reusing existing incomingKeygenMessages channel for DKG")
	}
	m.mu.Unlock()

	// 启动协议
	go func() {
		log.Info().
			Str("key_id", keyID).
			Str("this_node_id", thisNodeID).
			Str("msg_ch_ptr", fmt.Sprintf("%p", msgCh)).
			Msg("Starting LocalParty.Start for DKG")
		if err := party.Start(); err != nil {
			errCh <- err
		}
	}()

	// 启动消息处理循环：从队列读取消息并注入到party
	// 注意：tss-lib的消息处理机制是通过party的内部goroutine自动完成的
	// 接收到的消息字节需要解析并传递给party的内部处理机制
	// 由于tss-lib的LocalParty没有公开的Update方法，消息处理主要通过party的内部机制
	// 这里我们将消息字节暂存，等待party的内部机制处理
	// 实际的消息注入会在party的内部goroutine中自动完成
	go func() {
		log.Info().
			Str("key_id", keyID).
			Str("this_node_id", thisNodeID).
			Str("msg_ch_ptr", fmt.Sprintf("%p", msgCh)).
			Int("msg_ch_len", len(msgCh)).
			Msg("Starting message processing loop for DKG")
		for {
			select {
			case <-ctx.Done():
				log.Info().
					Str("key_id", keyID).
					Str("this_node_id", thisNodeID).
					Msg("Message processing loop stopped due to context cancellation")
				return
			case incomingMsg, ok := <-msgCh:
				if !ok {
					log.Info().
						Str("key_id", keyID).
						Str("this_node_id", thisNodeID).
						Msg("Message processing loop stopped: channel closed")
					return
				}
				log.Info().
					Str("key_id", keyID).
					Str("from_node_id", incomingMsg.fromNodeID).
					Bool("is_broadcast", incomingMsg.isBroadcast).
					Int("msg_bytes_len", len(incomingMsg.msgBytes)).
					Str("msg_ch_ptr", fmt.Sprintf("%p", msgCh)).
					Int("msg_ch_len", len(msgCh)).
					Msg("Received message in processing loop")

				// 获取LocalParty实例
				m.mu.RLock()
				localParty, exists := m.activeKeygen[keyID]
				m.mu.RUnlock()

				if !exists {
					log.Warn().
						Str("key_id", keyID).
						Str("from_node_id", incomingMsg.fromNodeID).
						Str("msg_ch_ptr", fmt.Sprintf("%p", msgCh)).
						Msg("LocalParty not yet created, message will be processed when party starts")
					// 如果LocalParty还未创建，等待一段时间后重试
					// 注意：消息已经在队列中，不会丢失
					time.Sleep(100 * time.Millisecond)
					continue
				}

				// 获取发送方的PartyID
				fromPartyID, ok := m.nodeIDToPartyID[incomingMsg.fromNodeID]
				if !ok {
					log.Warn().
						Str("from_node_id", incomingMsg.fromNodeID).
						Msg("PartyID not found for node")
					continue
				}

				// 使用UpdateFromBytes将消息注入到LocalParty
				// isBroadcast参数：如果消息是广播消息则为true，否则为false
				// 注意：tss-lib 的 UpdateFromBytes 方法必须被调用，否则 party 无法处理接收到的消息
				ok, tssErr := localParty.UpdateFromBytes(incomingMsg.msgBytes, fromPartyID, incomingMsg.isBroadcast)
				if !ok || tssErr != nil {
					log.Warn().
						Err(tssErr).
						Str("key_id", keyID).
						Str("from_node_id", incomingMsg.fromNodeID).
						Bool("is_broadcast", incomingMsg.isBroadcast).
						Int64("out_message_count", atomic.LoadInt64(&outMessageCount)).
						Int64("processed_message_count", atomic.LoadInt64(&processedMessageCount)).
						Msg("Failed to update local party from bytes")
					continue
				} else {
					atomic.AddInt64(&processedMessageCount, 1)
					lastMessageTime.Store(time.Now().UnixNano())
					log.Info().
						Str("key_id", keyID).
						Str("from_node_id", incomingMsg.fromNodeID).
						Bool("is_broadcast", incomingMsg.isBroadcast).
						Int64("out_message_count", atomic.LoadInt64(&outMessageCount)).
						Int64("processed_message_count", atomic.LoadInt64(&processedMessageCount)).
						Msg("Successfully updated local party from bytes")
				}
			}
		}
	}()

	// 处理消息和结果
	// 使用调用方上下文的截止时间作为超时，否则默认 10 分钟
	timeoutDur := 10 * time.Minute
	if deadline, ok := ctx.Deadline(); ok {
		timeoutDur = time.Until(deadline)
	}
	timeout := time.NewTimer(timeoutDur)
	defer timeout.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Warn().
				Str("key_id", keyID).
				Str("this_node_id", thisNodeID).
				Int64("out_message_count", atomic.LoadInt64(&outMessageCount)).
				Int64("processed_message_count", atomic.LoadInt64(&processedMessageCount)).
				Dur("since_last_message", time.Since(time.Unix(0, lastMessageTime.Load()))).
				Msg("DKG stopped due to context cancellation")
			return nil, ctx.Err()
		case <-timeout.C:
			log.Error().
				Str("key_id", keyID).
				Str("this_node_id", thisNodeID).
				Int64("out_message_count", atomic.LoadInt64(&outMessageCount)).
				Int64("processed_message_count", atomic.LoadInt64(&processedMessageCount)).
				Dur("since_last_message", time.Since(time.Unix(0, lastMessageTime.Load()))).
				Msg("DKG timeout reached")
			return nil, errors.New("keygen timeout")
		case msg := <-outCh:
			atomic.AddInt64(&outMessageCount, 1)
			lastMessageTime.Store(time.Now().UnixNano())
			// 路由消息到其他节点
			log.Info().
				Str("key_id", keyID).
				Str("this_node_id", thisNodeID).
				Int("target_count", len(msg.GetTo())).
				Str("message_type", fmt.Sprintf("%T", msg)).
				Msg("Received message from tss-lib outCh, routing to other nodes")
			if m.messageRouter == nil {
				return nil, errors.Errorf("messageRouter is nil (keyID: %s, thisNodeID: %s)", keyID, thisNodeID)
			}

			// 获取会话ID（keyID作为sessionID）
			sessionID := keyID
			m.mu.RLock()
			if mappedID, ok := m.sessionIDMap[keyID]; ok {
				sessionID = mappedID
			}
			m.mu.RUnlock()

			// 路由到所有目标节点
			targetNodes := msg.GetTo()
			if len(targetNodes) == 0 {
				// 广播消息：发送给所有其他节点，并在接收端以 isBroadcast=true 注入
				log.Info().
					Str("key_id", keyID).
					Str("this_node_id", thisNodeID).
					Int("party_count", len(m.nodeIDToPartyID)).
					Msg("Message has no target nodes, broadcasting to all other nodes (tss outCh)")

				// 获取所有其他节点的 PartyID
				m.mu.RLock()
				allPartyIDs := make([]*tss.PartyID, 0, len(m.nodeIDToPartyID))
				for nodeID, partyID := range m.nodeIDToPartyID {
					if nodeID != thisNodeID {
						allPartyIDs = append(allPartyIDs, partyID)
					}
				}
				m.mu.RUnlock()

				// 将消息发送给所有其他节点（标记 isBroadcast）
				for _, partyID := range allPartyIDs {
					targetNodeID, ok := m.partyIDToNodeID[partyID.Id]
					if !ok {
						log.Error().
							Str("partyID", partyID.Id).
							Str("keyID", keyID).
							Msg("Failed to find nodeID for partyID in broadcast")
						continue
					}

					log.Error().
						Str("keyID", keyID).
						Str("targetNodeID", targetNodeID).
						Str("partyID", partyID.Id).
						Msg("Broadcasting message to node (marked isBroadcast)")

					// 通过 messageRouter 发送（tss.Message 将在对端被序列化处理；标记广播语义由 UpdateFromBytes 的 isBroadcast 参数控制）
					if err := m.messageRouter(sessionID, targetNodeID, msg, true); err != nil {
						log.Error().
							Err(err).
							Str("keyID", keyID).
							Str("targetNodeID", targetNodeID).
							Msg("Failed to broadcast message to node")
						// 继续发送给其他节点，不因为一个节点失败而停止
					}
				}
				continue // 跳过下面的循环
			}

			for _, to := range targetNodes {
				targetNodeID, ok := m.partyIDToNodeID[to.Id]
				if !ok {
					// 获取所有可用的映射用于调试
					availableMappings := make(map[string]string)
					m.mu.RLock()
					for pid, nid := range m.partyIDToNodeID {
						availableMappings[pid] = nid
					}
					m.mu.RUnlock()
					return nil, errors.Errorf("party ID to node ID mapping not found: %s (keyID: %s, thisNodeID: %s, available mappings: %v)", to.Id, keyID, thisNodeID, availableMappings)
				}
				// 添加调试信息到错误消息
				if err := m.messageRouter(sessionID, targetNodeID, msg, false); err != nil {
					return nil, errors.Wrapf(err, "route message to node %s (keyID: %s, thisNodeID: %s, partyID: %s, sessionID: %s)", targetNodeID, keyID, thisNodeID, to.Id, sessionID)
				}
			}
		case saveData := <-endCh:
			log.Info().
				Str("key_id", keyID).
				Str("this_node_id", thisNodeID).
				Msg("DKG completed successfully, received LocalPartySaveData from endCh")
			m.mu.Lock()
			delete(m.activeKeygen, keyID)
			// 清理消息队列
			if ch, ok := m.incomingKeygenMessages[keyID]; ok {
				close(ch)
				delete(m.incomingKeygenMessages, keyID)
			}
			m.mu.Unlock()
			if saveData == nil {
				log.Error().
					Str("key_id", keyID).
					Str("this_node_id", thisNodeID).
					Msg("DKG completed but saveData is nil")
				return nil, errors.New("keygen returned nil save data")
			}
			log.Info().
				Str("key_id", keyID).
				Str("this_node_id", thisNodeID).
				Msg("DKG completed successfully, returning LocalPartySaveData")
			return saveData, nil
		case err := <-errCh:
			log.Error().
				Err(err).
				Str("key_id", keyID).
				Str("this_node_id", thisNodeID).
				Msg("DKG failed with error from errCh")
			m.mu.Lock()
			delete(m.activeKeygen, keyID)
			// 清理消息队列
			if ch, ok := m.incomingKeygenMessages[keyID]; ok {
				close(ch)
				delete(m.incomingKeygenMessages, keyID)
			}
			m.mu.Unlock()
			return nil, errors.Wrap(err, "keygen error")
		}
	}
}

// executeResharing 执行密钥轮换（Resharing）协议
func (m *tssPartyManager) executeResharing(
	ctx context.Context,
	keyID string,
	oldNodeIDs []string,
	newNodeIDs []string,
	threshold int,
	newThreshold int,
	thisNodeID string,
	keyData *keygen.LocalPartySaveData,
) (*keygen.LocalPartySaveData, error) {
	// 确保 oldNodeIDs 和 newNodeIDs 有序
	sortedOldNodeIDs := make([]string, len(oldNodeIDs))
	copy(sortedOldNodeIDs, oldNodeIDs)
	sort.Strings(sortedOldNodeIDs)

	sortedNewNodeIDs := make([]string, len(newNodeIDs))
	copy(sortedNewNodeIDs, newNodeIDs)
	sort.Strings(sortedNewNodeIDs)

	// 为旧委员会和新委员会设置 PartyID
	if err := m.setupPartyIDs(sortedOldNodeIDs); err != nil {
		return nil, errors.Wrap(err, "setup old party IDs")
	}
	if err := m.setupPartyIDs(sortedNewNodeIDs); err != nil {
		return nil, errors.Wrap(err, "setup new party IDs")
	}

	oldParties, err := m.getPartyIDs(sortedOldNodeIDs)
	if err != nil {
		return nil, errors.Wrap(err, "get old party IDs")
	}
	newParties, err := m.getPartyIDs(sortedNewNodeIDs)
	if err != nil {
		return nil, errors.Wrap(err, "get new party IDs")
	}

	thisPartyID, ok := m.nodeIDToPartyID[thisNodeID]
	if !ok {
		return nil, errors.Errorf("this node ID not found: %s", thisNodeID)
	}

	// 构建 Resharing 参数
	ctxTSS := tss.NewPeerContext(oldParties)
	newCtxTSS := tss.NewPeerContext(newParties)
	params := tss.NewReSharingParameters(tss.S256(), ctxTSS, newCtxTSS, thisPartyID, len(oldParties), threshold, len(newParties), newThreshold)

	// 创建消息通道
	outCh := make(chan tss.Message, len(oldParties)+len(newParties))
	endCh := make(chan *keygen.LocalPartySaveData, 1)
	errCh := make(chan *tss.Error, 1)

	// 创建 Resharing LocalParty
	party := resharing.NewLocalParty(params, *keyData, outCh, endCh)

	m.mu.Lock()
	if localParty, ok := party.(*resharing.LocalParty); ok {
		m.activeResharing[keyID] = localParty
	}
	m.sessionIDMap[keyID] = keyID
	m.sessionCreationTimes[keyID] = time.Now()
	m.mu.Unlock()

	// 创建消息队列
	m.mu.Lock()
	msgCh, exists := m.incomingResharingMessages[keyID]
	if !exists {
		msgCh = make(chan *incomingMessage, 100)
		m.incomingResharingMessages[keyID] = msgCh
	}
	m.mu.Unlock()

	// 启动协议
	go func() {
		if err := party.Start(); err != nil {
			errCh <- err
		}
	}()

	// 消息处理循环
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case incomingMsg, ok := <-msgCh:
				if !ok {
					return
				}

				m.mu.RLock()
				localParty, exists := m.activeResharing[keyID]
				m.mu.RUnlock()

				if !exists {
					time.Sleep(100 * time.Millisecond)
					continue
				}

				fromPartyID, ok := m.nodeIDToPartyID[incomingMsg.fromNodeID]
				if !ok {
					continue
				}

				_, _ = localParty.UpdateFromBytes(incomingMsg.msgBytes, fromPartyID, incomingMsg.isBroadcast)
			}
		}
	}()

	// 等待结果
	timeout := time.NewTimer(10 * time.Minute)
	defer timeout.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout.C:
			return nil, errors.New("resharing timeout")
		case msg := <-outCh:
			// 路由消息
			targetNodes := msg.GetTo()
			isBroadcast := len(targetNodes) == 0

			if m.messageRouter != nil {
				if isBroadcast {
					// 广播到旧节点和新节点
					targetNodeIDs := make(map[string]struct{})
					m.mu.RLock()
					for _, pid := range oldParties {
						if nid, ok := m.partyIDToNodeID[pid.Id]; ok && nid != thisNodeID {
							targetNodeIDs[nid] = struct{}{}
						}
					}
					for _, pid := range newParties {
						if nid, ok := m.partyIDToNodeID[pid.Id]; ok && nid != thisNodeID {
							targetNodeIDs[nid] = struct{}{}
						}
					}
					m.mu.RUnlock()

					for nid := range targetNodeIDs {
						m.messageRouter(keyID, nid, msg, true)
					}
				} else {
					for _, to := range targetNodes {
						if nid, ok := m.getNodeID(to.Id); ok {
							m.messageRouter(keyID, nid, msg, false)
						}
					}
				}
			}
		case saveData := <-endCh:
			m.mu.Lock()
			delete(m.activeResharing, keyID)
			if ch, ok := m.incomingResharingMessages[keyID]; ok {
				close(ch)
				delete(m.incomingResharingMessages, keyID)
			}
			m.mu.Unlock()
			return saveData, nil
		case err := <-errCh:
			m.mu.Lock()
			delete(m.activeResharing, keyID)
			if ch, ok := m.incomingResharingMessages[keyID]; ok {
				close(ch)
				delete(m.incomingResharingMessages, keyID)
			}
			m.mu.Unlock()
			return nil, errors.Wrap(err, "resharing error")
		}
	}
}

// ProcessIncomingResharingMessage 处理接收到的 Resharing 消息
func (m *tssPartyManager) ProcessIncomingResharingMessage(
	ctx context.Context,
	sessionID string,
	fromNodeID string,
	msgBytes []byte,
	isBroadcast bool,
) error {
	var msgCh chan *incomingMessage
	var exists bool

	// 等待队列创建
	waitTimeout := time.NewTimer(5 * time.Second)
	defer waitTimeout.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	// 首次检查
	m.mu.RLock()
	msgCh, exists = m.incomingResharingMessages[sessionID]
	m.mu.RUnlock()

	if !exists {
		for !exists {
			select {
			case <-waitTimeout.C:
				return errors.Errorf("timeout waiting for resharing message queue (session %s)", sessionID)
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				m.mu.RLock()
				msgCh, exists = m.incomingResharingMessages[sessionID]
				m.mu.RUnlock()
				if exists {
					break
				}
			}
		}
	}

	incomingMsg := &incomingMessage{
		msgBytes:    msgBytes,
		fromNodeID:  fromNodeID,
		isBroadcast: isBroadcast,
	}

	select {
	case msgCh <- incomingMsg:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return errors.Errorf("resharing message queue full for session %s", sessionID)
	}
}

// SigningOptions 签名执行选项
type SigningOptions struct {
	// Timeout 超时时间（默认 2 分钟）
	Timeout time.Duration
	// EnableIdentifiableAbort 是否支持可识别的中止（GG20 特性）
	EnableIdentifiableAbort bool
	// ProtocolName 协议名称（用于错误消息）
	ProtocolName string
}

// executeSigning 执行真正的阈值签名协议（通用实现，支持 GG18/GG20）
func (m *tssPartyManager) executeSigning(
	ctx context.Context,
	sessionID string,
	keyID string,
	message []byte,
	nodeIDs []string,
	thisNodeID string,
	keyData *keygen.LocalPartySaveData,
	opts TSSSigningOptions,
) (*common.SignatureData, error) {
	if err := m.setupPartyIDs(nodeIDs); err != nil {
		return nil, errors.Wrap(err, "setup party IDs")
	}

	parties, err := m.getPartyIDs(nodeIDs)
	if err != nil {
		return nil, errors.Wrap(err, "get party IDs")
	}

	thisPartyID, ok := m.getPartyID(thisNodeID)
	if !ok {
		return nil, errors.Errorf("this node ID not found: %s", thisNodeID)
	}

	ctxTSS := tss.NewPeerContext(parties)
	threshold := len(parties) - 1
	params := tss.NewParameters(tss.S256(), ctxTSS, thisPartyID, len(parties), threshold)

	log.Info().
		Str("session_id", sessionID).
		Str("this_node_id", thisNodeID).
		Str("this_party_id", thisPartyID.Id).
		Int("party_count", len(parties)).
		Int("threshold", threshold).
		Strs("party_ids", func() []string {
			ids := make([]string, len(parties))
			for i, p := range parties {
				ids[i] = p.Id
			}
			return ids
		}()).
		Msg("🔍 [DIAGNOSTIC] Created TSS parameters for signing")

	// 计算消息哈希
	hash := sha256.Sum256(message)
	msgBigInt := new(big.Int).SetBytes(hash[:])

	// 创建消息通道
	outCh := make(chan tss.Message, len(parties))
	endCh := make(chan *common.SignatureData, 1)
	errCh := make(chan *tss.Error, 1)

	// 创建 LocalParty
	party := signing.NewLocalParty(msgBigInt, params, *keyData, outCh, endCh)

	m.mu.Lock()
	// 类型断言为 *signing.LocalParty
	if localParty, ok := party.(*signing.LocalParty); ok {
		m.activeSigning[sessionID] = localParty
	}
	// 记录会话ID映射
	m.sessionIDMap[sessionID] = sessionID
	m.sessionCreationTimes[sessionID] = time.Now()
	m.mu.Unlock()

	// 创建消息队列（如果不存在）
	// 关键修复：executeSigning 创建队列后，直接使用这个队列引用传递给消息处理循环
	// 这样可以确保消息处理循环使用的是 executeSigning 创建的队列，而不是 ProcessIncomingSigningMessage 创建的新队列
	// 重要：队列必须在启动 LocalParty 之前创建，这样 ProcessIncomingSigningMessage 才能及时找到队列
	m.mu.Lock()
	var messageQueueForProcessing chan *incomingMessage
	existingMsgCh, exists := m.incomingSigningMessages[sessionID]
	if !exists {
		log.Info().
			Str("session_id", sessionID).
			Str("this_node_id", thisNodeID).
			Msg("🔍 [DIAGNOSTIC] executeSigning: creating new message queue (queue did not exist)")
		messageQueueForProcessing = make(chan *incomingMessage, 100)
		m.incomingSigningMessages[sessionID] = messageQueueForProcessing
		log.Info().
			Str("session_id", sessionID).
			Str("this_node_id", thisNodeID).
			Msg("🔍 [DIAGNOSTIC] executeSigning: message queue created and added to map")
	} else {
		log.Info().
			Str("session_id", sessionID).
			Str("this_node_id", thisNodeID).
			Msg("🔍 [DIAGNOSTIC] executeSigning: using existing message queue")
		messageQueueForProcessing = existingMsgCh
	}
	// 记录当前 map/activeSigning 状态，便于诊断队列可见性
	_, activeSigningExists := m.activeSigning[sessionID]
	log.Info().
		Str("session_id", sessionID).
		Str("this_node_id", thisNodeID).
		Bool("queue_in_map", true).
		Bool("active_signing_exists", activeSigningExists).
		Msg("🔍 [DIAGNOSTIC] executeSigning: queue state after creation")
	// 保存队列引用，供消息处理循环使用（避免从 map 重新获取，可能获取到不同的队列）
	m.mu.Unlock()

	// 启动协议
	go func() {
		if err := party.Start(); err != nil {
			errCh <- err
		}
	}()

	// 启动消息处理循环：从队列读取消息并注入到party
	// 使用tss-lib的UpdateFromBytes方法将消息注入到LocalParty
	// 关键修复：消息处理循环能够动态检测队列变化，即使 ProcessIncomingSigningMessage 创建了后备队列也能处理
	// 重要：消息处理循环必须在队列创建之后立即启动，这样 ProcessIncomingSigningMessage 放入的消息才能被及时处理
	go func() {
		log.Info().
			Str("session_id", sessionID).
			Str("this_node_id", thisNodeID).
			Msg("🔍 [DIAGNOSTIC] Starting message processing loop for signing")

		messageCount := 0
		// 首先使用 executeSigning 创建的队列引用
		msgCh := messageQueueForProcessing

		if msgCh == nil {
			log.Error().
				Str("session_id", sessionID).
				Str("this_node_id", thisNodeID).
				Msg("🔍 [DIAGNOSTIC] Message queue reference is nil, exiting")
			return
		}

		log.Info().
			Str("session_id", sessionID).
			Str("this_node_id", thisNodeID).
			Msg("🔍 [DIAGNOSTIC] Message queue reference is valid, entering message processing loop")

		// 消息处理循环：从队列读取消息并注入到 party
		// 注意：ProcessIncomingSigningMessage 不再创建后备队列，所以消息处理循环只需要专注于读取消息
		log.Info().
			Str("session_id", sessionID).
			Str("this_node_id", thisNodeID).
			Msg("🔍 [DIAGNOSTIC] Entering message processing select loop")

		for {
			// 如果队列为 nil，从 map 获取
			if msgCh == nil {
				m.mu.RLock()
				msgCh, _ = m.incomingSigningMessages[sessionID]
				m.mu.RUnlock()
				if msgCh == nil {
					log.Warn().
						Str("session_id", sessionID).
						Str("this_node_id", thisNodeID).
						Msg("🔍 [DIAGNOSTIC] Message queue not found in map, waiting...")
					time.Sleep(100 * time.Millisecond)
					continue
				}
				log.Info().
					Str("session_id", sessionID).
					Str("this_node_id", thisNodeID).
					Msg("🔍 [DIAGNOSTIC] Retrieved message queue from map")
			}

			select {
			case <-ctx.Done():
				log.Info().
					Str("session_id", sessionID).
					Str("this_node_id", thisNodeID).
					Int("total_messages_processed", messageCount).
					Msg("🔍 [DIAGNOSTIC] Message processing loop stopped due to context cancellation")
				return
			case incomingMsg, ok := <-msgCh:
				if !ok {
					// 队列被关闭，尝试从 map 重新获取队列（可能是 ProcessIncomingSigningMessage 创建了后备队列）
					log.Warn().
						Str("session_id", sessionID).
						Str("this_node_id", thisNodeID).
						Int("total_messages_processed", messageCount).
						Msg("🔍 [DIAGNOSTIC] Message queue closed, attempting to retrieve new queue from map")
					m.mu.RLock()
					msgCh, _ = m.incomingSigningMessages[sessionID]
					m.mu.RUnlock()
					if msgCh == nil {
						// 队列已被清理，协议已结束，正常退出循环
						log.Info().
							Str("session_id", sessionID).
							Str("this_node_id", thisNodeID).
							Int("total_messages_processed", messageCount).
							Msg("🔍 [DIAGNOSTIC] Message queue cleaned from map after channel closed, exiting processing loop")
						return
					}
					log.Info().
						Str("session_id", sessionID).
						Str("this_node_id", thisNodeID).
						Msg("🔍 [DIAGNOSTIC] Retrieved new message queue from map, continuing processing")
					continue
				}

				messageCount++
				log.Info().
					Str("session_id", sessionID).
					Str("this_node_id", thisNodeID).
					Str("from_node_id", incomingMsg.fromNodeID).
					Bool("is_broadcast", incomingMsg.isBroadcast).
					Int("msg_bytes_len", len(incomingMsg.msgBytes)).
					Int("message_count", messageCount).
					Msg("🔍 [DIAGNOSTIC] Received message in signing processing loop")

				// 获取LocalParty实例
				m.mu.RLock()
				localParty, exists := m.activeSigning[sessionID]
				m.mu.RUnlock()

				if !exists {
					// LocalParty还未创建或已结束，忽略消息
					log.Warn().
						Str("session_id", sessionID).
						Str("this_node_id", thisNodeID).
						Str("from_node_id", incomingMsg.fromNodeID).
						Msg("🔍 [DIAGNOSTIC] LocalParty not found, message will be ignored")
					continue
				}

				// 获取发送方的PartyID
				fromPartyID, ok := m.nodeIDToPartyID[incomingMsg.fromNodeID]
				if !ok {
					// 发送方节点ID未找到，忽略消息
					log.Warn().
						Str("session_id", sessionID).
						Str("this_node_id", thisNodeID).
						Str("from_node_id", incomingMsg.fromNodeID).
						Msg("🔍 [DIAGNOSTIC] PartyID not found for from_node_id, message will be ignored")
					continue
				}

				// 使用UpdateFromBytes将消息注入到LocalParty
				// isBroadcast参数：如果消息是广播消息则为true，否则为false
				log.Debug().
					Str("session_id", sessionID).
					Str("this_node_id", thisNodeID).
					Str("from_node_id", incomingMsg.fromNodeID).
					Str("from_party_id", fromPartyID.Id).
					Bool("is_broadcast", incomingMsg.isBroadcast).
					Msg("🔍 [DIAGNOSTIC] Calling UpdateFromBytes to inject message into LocalParty")

				ok, tssErr := localParty.UpdateFromBytes(incomingMsg.msgBytes, fromPartyID, incomingMsg.isBroadcast)
				if !ok || tssErr != nil {
					// 消息注入失败，记录错误但继续处理其他消息
					log.Error().
						Err(tssErr).
						Str("session_id", sessionID).
						Str("this_node_id", thisNodeID).
						Str("from_node_id", incomingMsg.fromNodeID).
						Bool("is_broadcast", incomingMsg.isBroadcast).
						Bool("update_ok", ok).
						Msg("🔍 [DIAGNOSTIC] Failed to update LocalParty from bytes")
					continue
				}

				log.Info().
					Str("session_id", sessionID).
					Str("this_node_id", thisNodeID).
					Str("from_node_id", incomingMsg.fromNodeID).
					Bool("is_broadcast", incomingMsg.isBroadcast).
					Msg("🔍 [DIAGNOSTIC] Successfully updated LocalParty from bytes")
			}
		}
	}()

	// 处理消息和结果
	if opts.Timeout == 0 {
		opts.Timeout = 2 * time.Minute // 默认超时
	}
	if opts.ProtocolName == "" {
		opts.ProtocolName = "TSS"
	}
	timeout := time.NewTimer(opts.Timeout)
	defer timeout.Stop()

	// ✅ 添加消息计数和状态跟踪
	outMessageCount := 0
	lastMessageTime := time.Now()

	log.Info().
		Str("session_id", sessionID).
		Str("this_node_id", thisNodeID).
		Str("protocol", opts.ProtocolName).
		Dur("timeout", opts.Timeout).
		Msg("🔍 [DIAGNOSTIC] Entering main signing loop, waiting for messages/results")

	for {
		select {
		case <-ctx.Done():
			log.Warn().
				Str("session_id", sessionID).
				Str("this_node_id", thisNodeID).
				Int("out_message_count", outMessageCount).
				Dur("last_message_age", time.Since(lastMessageTime)).
				Msg("🔍 [DIAGNOSTIC] Main signing loop canceled by context")
			return nil, ctx.Err()
		case <-timeout.C:
			log.Error().
				Str("session_id", sessionID).
				Str("this_node_id", thisNodeID).
				Str("protocol", opts.ProtocolName).
				Int("out_message_count", outMessageCount).
				Dur("last_message_age", time.Since(lastMessageTime)).
				Msg("🔍 [DIAGNOSTIC] Signing timeout - no signature received")
			return nil, errors.Errorf("%s signing timeout", opts.ProtocolName)
		case msg := <-outCh:
			// 路由消息到其他节点
			// ✅ 详细日志：记录消息类型、目标节点、广播状态、消息长度
			outMessageCount++
			lastMessageTime = time.Now()

			msgBytes, _, err := msg.WireBytes()
			if err != nil {
				log.Error().
					Err(err).
					Str("session_id", sessionID).
					Str("this_node_id", thisNodeID).
					Msg("🔍 [DIAGNOSTIC] Failed to serialize message for logging")
				msgBytes = []byte{}
			}
			msgType := fmt.Sprintf("%T", msg)
			targetNodes := msg.GetTo()
			isBroadcast := len(targetNodes) == 0

			log.Info().
				Str("session_id", sessionID).
				Str("this_node_id", thisNodeID).
				Int("out_message_count", outMessageCount).
				Dur("time_since_start", time.Since(lastMessageTime)).
				Msg("🔍 [DIAGNOSTIC] Received message from outCh (protocol is progressing)")

			log.Info().
				Str("session_id", sessionID).
				Str("this_node_id", thisNodeID).
				Str("message_type", msgType).
				Int("target_count", len(targetNodes)).
				Bool("is_broadcast", isBroadcast).
				Int("msg_bytes_len", len(msgBytes)).
				Strs("target_party_ids", func() []string {
					ids := make([]string, len(targetNodes))
					for i, to := range targetNodes {
						ids[i] = to.Id
					}
					return ids
				}()).
				Msg("🔍 [DIAGNOSTIC] Received message from tss-lib outCh in executeSigning")

			if m.messageRouter != nil {
				// 获取会话ID
				m.mu.RLock()
				currentSessionID := sessionID
				if mappedID, ok := m.sessionIDMap[sessionID]; ok {
					currentSessionID = mappedID
				}
				m.mu.RUnlock()

				if isBroadcast {
					// 广播到所有节点（SendSigningMessage 会自行跳过发送给自身）
					m.mu.RLock()
					allTargetNodeIDs := make([]string, 0, len(m.partyIDToNodeID))
					for _, targetNodeID := range m.partyIDToNodeID {
						if targetNodeID != thisNodeID {
							allTargetNodeIDs = append(allTargetNodeIDs, targetNodeID)
						}
					}
					m.mu.RUnlock()

					log.Info().
						Str("session_id", sessionID).
						Str("this_node_id", thisNodeID).
						Strs("target_node_ids", allTargetNodeIDs).
						Int("target_count", len(allTargetNodeIDs)).
						Msg("🔍 [DIAGNOSTIC] Broadcasting signing message to all nodes")

					for _, targetNodeID := range allTargetNodeIDs {
						if err := m.messageRouter(currentSessionID, targetNodeID, msg, true); err != nil {
							log.Error().
								Err(err).
								Str("session_id", sessionID).
								Str("this_node_id", thisNodeID).
								Str("target_node_id", targetNodeID).
								Msg("🔍 [DIAGNOSTIC] Failed to broadcast signing message")
							return nil, errors.Wrapf(err, "broadcast signing msg to node %s", targetNodeID)
						}
						log.Debug().
							Str("session_id", sessionID).
							Str("this_node_id", thisNodeID).
							Str("target_node_id", targetNodeID).
							Msg("🔍 [DIAGNOSTIC] Successfully broadcast signing message to node")
					}
				} else {
					// 路由到指定目标节点
					log.Info().
						Str("session_id", sessionID).
						Str("this_node_id", thisNodeID).
						Int("target_count", len(targetNodes)).
						Msg("🔍 [DIAGNOSTIC] Routing signing message to specific target nodes")

					for _, to := range targetNodes {
						targetNodeID, ok := m.getNodeID(to.Id)
						if !ok {
							return nil, errors.Errorf("party ID to node ID mapping not found: %s", to.Id)
						}

						log.Debug().
							Str("session_id", sessionID).
							Str("this_node_id", thisNodeID).
							Str("target_party_id", to.Id).
							Str("target_node_id", targetNodeID).
							Msg("🔍 [DIAGNOSTIC] Routing signing message to target node")

						if err := m.messageRouter(currentSessionID, targetNodeID, msg, false); err != nil {
							log.Error().
								Err(err).
								Str("session_id", sessionID).
								Str("this_node_id", thisNodeID).
								Str("target_node_id", targetNodeID).
								Msg("🔍 [DIAGNOSTIC] Failed to route signing message")
							return nil, errors.Wrapf(err, "route message to node %s", targetNodeID)
						}

						log.Debug().
							Str("session_id", sessionID).
							Str("this_node_id", thisNodeID).
							Str("target_node_id", targetNodeID).
							Msg("🔍 [DIAGNOSTIC] Successfully routed signing message to target node")
					}
				}
			} else {
				log.Error().
					Str("session_id", sessionID).
					Str("this_node_id", thisNodeID).
					Msg("🔍 [DIAGNOSTIC] messageRouter is nil, cannot route signing message")
			}
		case sigData := <-endCh:
			log.Info().
				Str("session_id", sessionID).
				Str("this_node_id", thisNodeID).
				Str("protocol", opts.ProtocolName).
				Int("out_message_count", outMessageCount).
				Dur("total_duration", time.Since(lastMessageTime)).
				Msg("🔍 [DIAGNOSTIC] Received signature from endCh (signing completed successfully)")

			m.mu.Lock()
			delete(m.activeSigning, sessionID)
			// 清理消息队列
			if ch, ok := m.incomingSigningMessages[sessionID]; ok {
				close(ch)
				delete(m.incomingSigningMessages, sessionID)
			}
			m.mu.Unlock()
			if sigData == nil {
				log.Error().
					Str("session_id", sessionID).
					Str("this_node_id", thisNodeID).
					Msg("🔍 [DIAGNOSTIC] Signature data is nil")
				return nil, errors.Errorf("%s signing returned nil signature data", opts.ProtocolName)
			}
			log.Info().
				Str("session_id", sessionID).
				Str("this_node_id", thisNodeID).
				Int("r_bytes_len", len(sigData.R)).
				Int("s_bytes_len", len(sigData.S)).
				Msg("🔍 [DIAGNOSTIC] Returning signature data")
			return sigData, nil
		case err := <-errCh:
			log.Error().
				Err(err).
				Str("session_id", sessionID).
				Str("this_node_id", thisNodeID).
				Str("protocol", opts.ProtocolName).
				Int("out_message_count", outMessageCount).
				Dur("last_message_age", time.Since(lastMessageTime)).
				Msg("🔍 [DIAGNOSTIC] Received error from errCh (LocalParty.Start() or protocol error)")

			m.mu.Lock()
			delete(m.activeSigning, sessionID)
			// 清理消息队列
			if ch, ok := m.incomingSigningMessages[sessionID]; ok {
				close(ch)
				delete(m.incomingSigningMessages, sessionID)
			}
			m.mu.Unlock()
			// 如果支持可识别的中止，可以识别恶意节点
			if opts.EnableIdentifiableAbort && err.Culprits() != nil {
				log.Error().
					Str("session_id", sessionID).
					Str("this_node_id", thisNodeID).
					Interface("culprits", err.Culprits()).
					Msg("🔍 [DIAGNOSTIC] Identifiable abort detected")
				return nil, errors.Wrapf(err, "%s signing error (identifiable abort: %v)", opts.ProtocolName, err.Culprits())
			}
			return nil, errors.Wrapf(err, "%s signing error", opts.ProtocolName)
		}
	}
}

// ProcessIncomingKeygenMessage 处理接收到的DKG消息
// 找到对应的活跃keygen.LocalParty实例，解析消息并更新Party状态
func (m *tssPartyManager) ProcessIncomingKeygenMessage(
	ctx context.Context,
	sessionID string,
	fromNodeID string,
	msgBytes []byte,
	isBroadcast bool,
) error {
	// 将消息放入队列，由 executeKeygen 中的消息处理循环读取
	// 不再在此处创建新队列，确保发送和接收使用同一个 channel
	var msgCh chan *incomingMessage
	var exists bool

	// 先快速检查
	m.mu.RLock()
	msgCh, exists = m.incomingKeygenMessages[sessionID]
	m.mu.RUnlock()

	if !exists {
		// 等待队列创建（最多等待 5 秒，10ms 间隔）
		waitTimeout := time.NewTimer(5 * time.Second)
		defer waitTimeout.Stop()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()

		waitCount := 0
		for !exists {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-waitTimeout.C:
				m.mu.RLock()
				_, activeKeygenExists := m.activeKeygen[sessionID]
				m.mu.RUnlock()
				log.Error().
					Str("session_id", sessionID).
					Str("from_node_id", fromNodeID).
					Int("wait_iterations", waitCount).
					Dur("wait_duration", time.Duration(waitCount)*10*time.Millisecond).
					Bool("active_keygen_exists", activeKeygenExists).
					Msg("ProcessIncomingKeygenMessage: timeout waiting for existing queue, returning error")
				return errors.Errorf("timeout waiting for keygen message queue (session %s, waited %d iterations)", sessionID, waitCount)
			case <-ticker.C:
				waitCount++
				m.mu.RLock()
				msgCh, exists = m.incomingKeygenMessages[sessionID]
				m.mu.RUnlock()
				if exists {
					log.Debug().
						Str("session_id", sessionID).
						Str("from_node_id", fromNodeID).
						Int("wait_iterations", waitCount).
						Dur("wait_duration", time.Duration(waitCount)*10*time.Millisecond).
						Msg("ProcessIncomingKeygenMessage: found existing message queue")
					break
				}
				if waitCount%100 == 0 {
					log.Debug().
						Str("session_id", sessionID).
						Str("from_node_id", fromNodeID).
						Int("wait_iterations", waitCount).
						Dur("wait_duration", time.Duration(waitCount)*10*time.Millisecond).
						Msg("ProcessIncomingKeygenMessage: still waiting for message queue...")
				}
			}
		}
	}

	// 创建消息对象
	incomingMsg := &incomingMessage{
		msgBytes:    msgBytes,
		fromNodeID:  fromNodeID,
		isBroadcast: isBroadcast,
	}

	// 检查是否有活跃的DKG实例（支持 ECDSA 和 EdDSA）
	m.mu.RLock()
	_, hasActiveKeygen := m.activeKeygen[sessionID]
	_, hasActiveEdDSAKeygen := m.activeEdDSAKeygen[sessionID]
	m.mu.RUnlock()

	log.Debug().
		Str("session_id", sessionID).
		Str("from_node_id", fromNodeID).
		Bool("is_broadcast", isBroadcast).
		Int("msg_bytes_len", len(msgBytes)).
		Bool("has_active_keygen", hasActiveKeygen).
		Bool("has_active_eddsa_keygen", hasActiveEdDSAKeygen).
		Bool("queue_exists", exists).
		Str("msg_ch_ptr", fmt.Sprintf("%p", msgCh)).
		Int("msg_ch_len", len(msgCh)).
		Msg("Processing incoming DKG message")

	// 非阻塞发送
	select {
	case msgCh <- incomingMsg:
		// 消息已放入队列，由executeKeygen中的消息处理循环处理
		log.Debug().
			Str("session_id", sessionID).
			Str("from_node_id", fromNodeID).
			Int("msg_ch_len", len(msgCh)).
			Msg("Message enqueued successfully")
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		log.Warn().
			Str("session_id", sessionID).
			Str("from_node_id", fromNodeID).
			Msg("Keygen message queue full, message dropped")
		return errors.Errorf("keygen message queue full for session %s", sessionID)
	}
}

// ProcessIncomingSigningMessage 处理接收到的签名消息
// 找到对应的活跃signing.LocalParty实例，解析消息并更新Party状态
func (m *tssPartyManager) ProcessIncomingSigningMessage(
	ctx context.Context,
	sessionID string,
	fromNodeID string,
	msgBytes []byte,
	isBroadcast bool,
) error {
	// 将消息放入队列，由executeSigning中的消息处理循环处理
	// 关键修复：使用更高效的等待机制（10ms ticker 替代 100ms 轮询）
	// 这样可以更快检测到队列创建，减少等待时间
	var msgCh chan *incomingMessage
	var exists bool

	// 等待队列创建（最多等待 10 秒，但使用更短的检查间隔）
	waitTimeout := time.NewTimer(10 * time.Second)
	defer waitTimeout.Stop()
	ticker := time.NewTicker(10 * time.Millisecond) // 从 100ms 改为 10ms，提高检测频率
	defer ticker.Stop()

	// 第一次快速检查（不等待）
	m.mu.RLock()
	msgCh, exists = m.incomingSigningMessages[sessionID]
	m.mu.RUnlock()

	if exists {
		log.Debug().
			Str("session_id", sessionID).
			Str("from_node_id", fromNodeID).
			Msg("🔍 [DIAGNOSTIC] ProcessIncomingSigningMessage: found existing message queue immediately")
	} else {
		log.Debug().
			Str("session_id", sessionID).
			Str("from_node_id", fromNodeID).
			Msg("🔍 [DIAGNOSTIC] ProcessIncomingSigningMessage: queue not found, waiting for creation...")

		// 等待队列创建
		waitCount := 0
		for !exists {
			select {
			case <-waitTimeout.C:
				// 超时后，如果队列仍然不存在，返回错误（不再创建后备队列）
				// 这样可以避免创建多个队列导致消息丢失的问题
				m.mu.RLock()
				_, queueExists := m.incomingSigningMessages[sessionID]
				_, activeSigningExists := m.activeSigning[sessionID]
				m.mu.RUnlock()
				log.Error().
					Str("session_id", sessionID).
					Str("from_node_id", fromNodeID).
					Int("wait_iterations", waitCount).
					Dur("wait_duration", time.Duration(waitCount)*10*time.Millisecond).
					Bool("queue_exists", queueExists).
					Bool("active_signing_exists", activeSigningExists).
					Msg("🔍 [DIAGNOSTIC] ProcessIncomingSigningMessage: timeout waiting for queue, returning error")
				// 最后一次检查，确保队列真的不存在
				m.mu.RLock()
				msgCh, exists = m.incomingSigningMessages[sessionID]
				m.mu.RUnlock()
				if !exists {
					return errors.Errorf("timeout waiting for signing message queue (session %s, waited %d iterations)", sessionID, waitCount)
				}
				// 如果队列存在，继续处理（可能在最后一次检查时队列被创建了）
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				// 每 10ms 检查一次（而不是 100ms），更快检测到队列创建
				waitCount++
				m.mu.RLock()
				msgCh, exists = m.incomingSigningMessages[sessionID]
				m.mu.RUnlock()

				if exists {
					log.Debug().
						Str("session_id", sessionID).
						Str("from_node_id", fromNodeID).
						Int("wait_iterations", waitCount).
						Dur("wait_duration", time.Duration(waitCount)*10*time.Millisecond).
						Msg("🔍 [DIAGNOSTIC] ProcessIncomingSigningMessage: found existing message queue")
					// exists 为 true 时，for !exists 循环会自动退出，不需要 break
				}

				if waitCount%100 == 0 {
					// 每 1 秒（100 * 10ms）记录一次日志，减少日志输出
					log.Debug().
						Str("session_id", sessionID).
						Str("from_node_id", fromNodeID).
						Int("wait_iterations", waitCount).
						Dur("wait_duration", time.Duration(waitCount)*10*time.Millisecond).
						Msg("🔍 [DIAGNOSTIC] ProcessIncomingSigningMessage: still waiting for message queue creation...")
				}
			}
		}
	}

	if msgCh == nil {
		return errors.Errorf("failed to get or create message queue for session %s", sessionID)
	}

	// 创建消息对象
	incomingMsg := &incomingMessage{
		msgBytes:    msgBytes,
		fromNodeID:  fromNodeID,
		isBroadcast: isBroadcast,
	}

	log.Info().
		Str("session_id", sessionID).
		Str("from_node_id", fromNodeID).
		Bool("is_broadcast", isBroadcast).
		Int("msg_bytes_len", len(msgBytes)).
		Msg("🔍 [DIAGNOSTIC] ProcessIncomingSigningMessage: attempting to enqueue message")

	// 非阻塞发送
	select {
	case msgCh <- incomingMsg:
		// 消息已放入队列，由executeSigning中的消息处理循环处理
		log.Info().
			Str("session_id", sessionID).
			Str("from_node_id", fromNodeID).
			Bool("is_broadcast", isBroadcast).
			Msg("🔍 [DIAGNOSTIC] ProcessIncomingSigningMessage: message enqueued successfully")
		return nil
	case <-ctx.Done():
		log.Warn().
			Str("session_id", sessionID).
			Str("from_node_id", fromNodeID).
			Msg("🔍 [DIAGNOSTIC] ProcessIncomingSigningMessage: context canceled while enqueueing")
		return ctx.Err()
	default:
		log.Error().
			Str("session_id", sessionID).
			Str("from_node_id", fromNodeID).
			Msg("🔍 [DIAGNOSTIC] ProcessIncomingSigningMessage: message queue full")
		return errors.Errorf("signing message queue full for session %s", sessionID)
	}
}

// convertTSSKeyData 将 tss-lib 的保存数据转换为我们的 KeyShare 格式
// 注意：在tss-lib架构中，每个节点只保存自己的LocalPartySaveData
// 此函数只返回当前节点的KeyShare，不返回其他节点的
func convertTSSKeyData(
	keyID string,
	saveData *keygen.LocalPartySaveData,
	thisNodeID string,
) (*KeyShare, *PublicKey, error) {
	// 获取公钥（通过 ECDSA 公钥转换）
	ecdsaPubKey := saveData.ECDSAPub.ToECDSAPubKey()
	if ecdsaPubKey == nil {
		return nil, nil, errors.New("failed to convert ECPoint to ECDSA public key")
	}

	// 将 ECDSA 公钥序列化为压缩格式
	// secp256k1 压缩公钥：0x02/0x03 + 32字节 X坐标
	var pubKeyBytes []byte
	if ecdsaPubKey.Y.Bit(0) == 0 {
		pubKeyBytes = append([]byte{0x02}, ecdsaPubKey.X.Bytes()...)
	} else {
		pubKeyBytes = append([]byte{0x03}, ecdsaPubKey.X.Bytes()...)
	}
	// 确保 X 坐标是 32 字节
	if len(ecdsaPubKey.X.Bytes()) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(ecdsaPubKey.X.Bytes()):], ecdsaPubKey.X.Bytes())
		if ecdsaPubKey.Y.Bit(0) == 0 {
			pubKeyBytes = append([]byte{0x02}, padded...)
		} else {
			pubKeyBytes = append([]byte{0x03}, padded...)
		}
	}
	pubKeyHex := hex.EncodeToString(pubKeyBytes)

	publicKey := &PublicKey{
		Bytes: pubKeyBytes,
		Hex:   pubKeyHex,
	}

	// 从 saveData 中提取当前节点的私钥分片 Xi
	// LocalPartySaveData.Xi 是当前节点的私钥分片
	xiBytes := saveData.Xi.Bytes()

	// 确保Xi是32字节
	xiPadded := make([]byte, 32)
	copy(xiPadded[32-len(xiBytes):], xiBytes)

	// 创建当前节点的KeyShare
	shareID := fmt.Sprintf("%s-%s", keyID, thisNodeID)
	// ShareID是big.Int，需要转换为int（使用低32位）
	shareIDInt := int(saveData.ShareID.Int64())
	if shareIDInt < 0 {
		// 如果转换失败，使用默认值1
		shareIDInt = 1
	}
	keyShare := &KeyShare{
		ShareID: shareID,
		NodeID:  thisNodeID,
		Share:   xiPadded,
		Index:   shareIDInt,
	}

	return keyShare, publicKey, nil
}

// convertTSSSignature 将 tss-lib 的签名数据转换为我们的 Signature 格式
func convertTSSSignature(sigData *common.SignatureData) (*Signature, error) {
	if sigData == nil {
		return nil, errors.New("signature data is nil")
	}

	// tss-lib 的签名是 (R, S) 格式，已经是 []byte
	rBytes := sigData.R
	sBytes := sigData.S

	// 填充到 32 字节
	rPadded := padScalarBytes(rBytes)
	sPadded := padScalarBytes(sBytes)

	// 构建 DER 编码的签名
	der := buildDERSignature(rPadded, sPadded)

	return &Signature{
		R:     rPadded,
		S:     sPadded,
		Bytes: der,
		Hex:   hex.EncodeToString(der),
	}, nil
}

func buildDERSignature(r, s []byte) []byte {
	// 简化的 DER 编码实现
	// 实际应该使用标准的 DER 编码库
	der := make([]byte, 0, 70)
	der = append(der, 0x30) // SEQUENCE
	der = append(der, byte(len(r)+len(s)+4))
	der = append(der, 0x02) // INTEGER
	der = append(der, byte(len(r)))
	der = append(der, r...)
	der = append(der, 0x02) // INTEGER
	der = append(der, byte(len(s)))
	der = append(der, s...)
	return der
}

func padScalarBytes(src []byte) []byte {
	const size = 32
	if len(src) >= size {
		return append([]byte(nil), src[len(src)-size:]...)
	}
	dst := make([]byte, size)
	copy(dst[size-len(src):], src)
	return dst
}

// executeEdDSAKeygen 执行 EdDSA DKG 协议（用于 FROST）
func (m *tssPartyManager) executeEdDSAKeygen(
	ctx context.Context,
	keyID string,
	nodeIDs []string,
	threshold int,
	thisNodeID string,
) (*eddsaKeygen.LocalPartySaveData, error) {
	if err := m.setupPartyIDs(nodeIDs); err != nil {
		return nil, errors.Wrap(err, "setup party IDs")
	}

	parties, err := m.getPartyIDs(nodeIDs)
	if err != nil {
		return nil, errors.Wrap(err, "get party IDs")
	}

	thisPartyID, ok := m.nodeIDToPartyID[thisNodeID]
	if !ok {
		return nil, errors.Errorf("this node ID not found: %s", thisNodeID)
	}

	ctxTSS := tss.NewPeerContext(parties)
	params := tss.NewParameters(tss.Edwards(), ctxTSS, thisPartyID, len(parties), threshold)

	// 创建消息通道
	outCh := make(chan tss.Message, len(parties))
	endCh := make(chan *eddsaKeygen.LocalPartySaveData, 1)
	errCh := make(chan *tss.Error, 1)

	// 创建 EdDSA LocalParty
	party := eddsaKeygen.NewLocalParty(params, outCh, endCh)

	m.mu.Lock()
	if localParty, ok := party.(*eddsaKeygen.LocalParty); ok {
		m.activeEdDSAKeygen[keyID] = localParty
	}
	// 记录会话ID映射（keyID作为sessionID）
	m.sessionIDMap[keyID] = keyID
	m.sessionCreationTimes[keyID] = time.Now()
	m.mu.Unlock()

	// 创建消息队列（如果不存在）
	m.mu.Lock()
	msgCh, exists := m.incomingKeygenMessages[keyID]
	if !exists {
		msgCh = make(chan *incomingMessage, 100)
		m.incomingKeygenMessages[keyID] = msgCh
		log.Info().
			Str("key_id", keyID).
			Msg("Created incomingKeygenMessages channel for EdDSA DKG")
	} else {
		log.Info().
			Str("key_id", keyID).
			Msg("Reusing existing incomingKeygenMessages channel for EdDSA DKG")
	}
	m.mu.Unlock()

	// 启动协议
	go func() {
		if err := party.Start(); err != nil {
			errCh <- err
		}
	}()

	// 启动消息处理循环：从队列读取消息并注入到party
	go func() {
		log.Info().
			Str("key_id", keyID).
			Str("this_node_id", thisNodeID).
			Msg("Starting message processing loop for EdDSA DKG")
		for {
			select {
			case <-ctx.Done():
				log.Info().
					Str("key_id", keyID).
					Str("this_node_id", thisNodeID).
					Msg("EdDSA DKG message processing loop stopped due to context cancellation")
				return
			case incomingMsg, ok := <-msgCh:
				if !ok {
					log.Info().
						Str("key_id", keyID).
						Str("this_node_id", thisNodeID).
						Msg("EdDSA DKG message processing loop stopped: channel closed")
					return
				}
				log.Debug().
					Str("key_id", keyID).
					Str("from_node_id", incomingMsg.fromNodeID).
					Bool("is_broadcast", incomingMsg.isBroadcast).
					Int("msg_bytes_len", len(incomingMsg.msgBytes)).
					Msg("Received message in EdDSA DKG processing loop")

				// 获取LocalParty实例
				m.mu.RLock()
				localParty, exists := m.activeEdDSAKeygen[keyID]
				m.mu.RUnlock()

				if !exists {
					log.Debug().
						Str("key_id", keyID).
						Str("from_node_id", incomingMsg.fromNodeID).
						Msg("EdDSA LocalParty not yet created, message will be processed when party starts")
					time.Sleep(100 * time.Millisecond)
					continue
				}

				// 获取发送方的PartyID
				fromPartyID, ok := m.nodeIDToPartyID[incomingMsg.fromNodeID]
				if !ok {
					log.Warn().
						Str("from_node_id", incomingMsg.fromNodeID).
						Str("key_id", keyID).
						Msg("PartyID not found for node in EdDSA DKG")
					continue
				}

				// 使用UpdateFromBytes将消息注入到LocalParty
				ok, tssErr := localParty.UpdateFromBytes(incomingMsg.msgBytes, fromPartyID, incomingMsg.isBroadcast)
				if !ok || tssErr != nil {
					log.Warn().
						Err(tssErr).
						Str("key_id", keyID).
						Str("from_node_id", incomingMsg.fromNodeID).
						Bool("is_broadcast", incomingMsg.isBroadcast).
						Msg("Failed to update EdDSA local party from bytes")
					continue
				} else {
					log.Debug().
						Str("key_id", keyID).
						Str("from_node_id", incomingMsg.fromNodeID).
						Bool("is_broadcast", incomingMsg.isBroadcast).
						Msg("Successfully updated EdDSA local party from bytes")
				}
			}
		}
	}()

	// 处理消息和结果
	timeout := time.NewTimer(10 * time.Minute)
	defer timeout.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout.C:
			return nil, errors.New("EdDSA keygen timeout")
		case msg := <-outCh:
			// 路由消息到其他节点
			if m.messageRouter == nil {
				return nil, errors.Errorf("messageRouter is nil (keyID: %s, thisNodeID: %s)", keyID, thisNodeID)
			}

			// 获取会话ID（keyID作为sessionID）
			sessionID := keyID
			m.mu.RLock()
			if mappedID, ok := m.sessionIDMap[keyID]; ok {
				sessionID = mappedID
			}
			m.mu.RUnlock()

			targetNodes := msg.GetTo()
			log.Debug().
				Str("key_id", keyID).
				Str("this_node_id", thisNodeID).
				Int("target_count", len(targetNodes)).
				Str("message_type", fmt.Sprintf("%T", msg)).
				Msg("Received message from EdDSA tss-lib outCh, routing to other nodes")

			// 处理广播消息（targetCount=0）
			if len(targetNodes) == 0 {
				// 广播消息：发送给所有其他节点
				log.Info().
					Str("key_id", keyID).
					Str("this_node_id", thisNodeID).
					Int("party_count", len(m.nodeIDToPartyID)).
					Msg("EdDSA DKG message has no target nodes, broadcasting to all other nodes")

				// 获取所有其他节点的 PartyID
				m.mu.RLock()
				allPartyIDs := make([]*tss.PartyID, 0, len(m.nodeIDToPartyID))
				for nodeID, partyID := range m.nodeIDToPartyID {
					if nodeID != thisNodeID {
						allPartyIDs = append(allPartyIDs, partyID)
					}
				}
				m.mu.RUnlock()

				// 将消息发送给所有其他节点（标记 isBroadcast）
				for _, partyID := range allPartyIDs {
					targetNodeID, ok := m.partyIDToNodeID[partyID.Id]
					if !ok {
						log.Error().
							Str("partyID", partyID.Id).
							Str("keyID", keyID).
							Msg("Failed to find nodeID for partyID in EdDSA DKG broadcast")
						continue
					}

					log.Info().
						Str("keyID", keyID).
						Str("targetNodeID", targetNodeID).
						Str("partyID", partyID.Id).
						Msg("Broadcasting EdDSA DKG message to node (marked isBroadcast)")

					if err := m.messageRouter(sessionID, targetNodeID, msg, true); err != nil {
						log.Error().
							Err(err).
							Str("keyID", keyID).
							Str("targetNodeID", targetNodeID).
							Msg("Failed to broadcast EdDSA DKG message to node")
						// 继续发送给其他节点，不因为一个节点失败而停止
					}
				}
				continue // 跳过下面的循环
			}

			// 处理定向消息
			for _, to := range targetNodes {
				targetNodeID, ok := m.getNodeID(to.Id)
				if !ok {
					return nil, errors.Errorf("party ID to node ID mapping not found: %s", to.Id)
				}
				if err := m.messageRouter(sessionID, targetNodeID, msg, false); err != nil {
					return nil, errors.Wrapf(err, "route EdDSA DKG message to node %s", targetNodeID)
				}
			}
		case saveData := <-endCh:
			m.mu.Lock()
			delete(m.activeEdDSAKeygen, keyID)
			// 清理消息队列
			if ch, ok := m.incomingKeygenMessages[keyID]; ok {
				close(ch)
				delete(m.incomingKeygenMessages, keyID)
			}
			m.mu.Unlock()
			if saveData == nil {
				return nil, errors.New("EdDSA keygen returned nil save data")
			}
			return saveData, nil
		case err := <-errCh:
			m.mu.Lock()
			delete(m.activeEdDSAKeygen, keyID)
			// 清理消息队列
			if ch, ok := m.incomingKeygenMessages[keyID]; ok {
				close(ch)
				delete(m.incomingKeygenMessages, keyID)
			}
			m.mu.Unlock()
			return nil, errors.Wrap(err, "EdDSA keygen error")
		}
	}
}

// executeEdDSASigning 执行 EdDSA 签名协议（用于 FROST，2 轮）
func (m *tssPartyManager) executeEdDSASigning(
	ctx context.Context,
	sessionID string,
	keyID string,
	message []byte,
	nodeIDs []string,
	thisNodeID string,
	keyData *eddsaKeygen.LocalPartySaveData,
	opts TSSSigningOptions,
) (*common.SignatureData, error) {
	if err := m.setupPartyIDs(nodeIDs); err != nil {
		return nil, errors.Wrap(err, "setup party IDs")
	}

	parties, err := m.getPartyIDs(nodeIDs)
	if err != nil {
		return nil, errors.Wrap(err, "get party IDs")
	}

	thisPartyID, ok := m.nodeIDToPartyID[thisNodeID]
	if !ok {
		return nil, errors.Errorf("this node ID not found: %s", thisNodeID)
	}

	ctxTSS := tss.NewPeerContext(parties)
	params := tss.NewParameters(tss.Edwards(), ctxTSS, thisPartyID, len(parties), len(parties)-1)

	// 使用原始消息（tss-lib v0.1 已支持标准 Ed25519，内部会使用 SHA-512）
	// 注意：tss-lib v0.1 已修改为支持标准 Ed25519，不再需要 SHA-256 哈希
	// 重要：使用 fullBytesLen 参数确保消息的完整长度（包括前导零）被正确保留
	msgBigInt := new(big.Int).SetBytes(message)
	messageLen := len(message)

	log.Debug().
		Str("session_id", sessionID).
		Int("message_length", messageLen).
		Str("message_hex", hex.EncodeToString(message)).
		Str("msg_big_int", msgBigInt.String()).
		Msg("🔍 [DIAGNOSTIC] executeEdDSASigning: message preparation for EdDSA signing")

	// 创建消息通道
	outCh := make(chan tss.Message, len(parties))
	endCh := make(chan *common.SignatureData, 1)
	errCh := make(chan *tss.Error, 1)

	// 创建 EdDSA LocalParty（FROST 使用 EdDSA signing，2 轮）
	// 传递 fullBytesLen 参数以确保消息的完整长度（包括前导零）被正确保留
	party := eddsaSigning.NewLocalParty(msgBigInt, params, *keyData, outCh, endCh, messageLen)

	m.mu.Lock()
	if localParty, ok := party.(*eddsaSigning.LocalParty); ok {
		m.activeEdDSASigning[sessionID] = localParty
	}
	// 记录会话ID映射
	m.sessionIDMap[sessionID] = sessionID
	m.sessionCreationTimes[sessionID] = time.Now()

	// 创建消息队列（如果不存在）
	// 重要：队列必须在启动 LocalParty 之前创建，这样 ProcessIncomingSigningMessage 才能及时找到队列
	var messageQueueForProcessing chan *incomingMessage
	existingMsgCh, exists := m.incomingSigningMessages[sessionID]
	if !exists {
		log.Info().
			Str("session_id", sessionID).
			Str("this_node_id", thisNodeID).
			Msg("🔍 [DIAGNOSTIC] executeEdDSASigning: creating new message queue")
		messageQueueForProcessing = make(chan *incomingMessage, 100)
		m.incomingSigningMessages[sessionID] = messageQueueForProcessing
	} else {
		log.Info().
			Str("session_id", sessionID).
			Str("this_node_id", thisNodeID).
			Msg("🔍 [DIAGNOSTIC] executeEdDSASigning: using existing message queue")
		messageQueueForProcessing = existingMsgCh
	}
	m.mu.Unlock()

	// 启动协议
	go func() {
		log.Info().
			Str("session_id", sessionID).
			Str("this_node_id", thisNodeID).
			Msg("🔍 [DIAGNOSTIC] Starting EdDSA signing party")
		if err := party.Start(); err != nil {
			log.Error().
				Err(err).
				Str("session_id", sessionID).
				Str("this_node_id", thisNodeID).
				Msg("🔍 [DIAGNOSTIC] EdDSA signing party.Start() failed")
			errCh <- err
		} else {
			log.Info().
				Str("session_id", sessionID).
				Str("this_node_id", thisNodeID).
				Msg("🔍 [DIAGNOSTIC] EdDSA signing party.Start() completed successfully")
		}
	}()

	// 启动消息处理循环：从队列读取消息并注入到party
	go func() {
		log.Info().
			Str("session_id", sessionID).
			Str("this_node_id", thisNodeID).
			Msg("🔍 [DIAGNOSTIC] Starting message processing loop for EdDSA signing")

		messageCount := 0
		msgCh := messageQueueForProcessing

		for {
			// 如果队列为 nil，从 map 获取
			if msgCh == nil {
				m.mu.RLock()
				msgCh, _ = m.incomingSigningMessages[sessionID]
				m.mu.RUnlock()
				if msgCh == nil {
					time.Sleep(100 * time.Millisecond)
					continue
				}
			}

			select {
			case <-ctx.Done():
				return
			case incomingMsg, ok := <-msgCh:
				if !ok {
					// 队列被关闭，尝试从 map 重新获取队列
					m.mu.RLock()
					msgCh, _ = m.incomingSigningMessages[sessionID]
					m.mu.RUnlock()
					if msgCh == nil {
						return
					}
					continue
				}

				messageCount++
				log.Debug().
					Str("session_id", sessionID).
					Str("from_node_id", incomingMsg.fromNodeID).
					Int("message_count", messageCount).
					Msg("🔍 [DIAGNOSTIC] Processing incoming EdDSA signing message")

				// 获取 LocalParty 实例
				m.mu.RLock()
				localParty, exists := m.activeEdDSASigning[sessionID]
				m.mu.RUnlock()

				if !exists {
					log.Warn().
						Str("session_id", sessionID).
						Str("from_node_id", incomingMsg.fromNodeID).
						Msg("🔍 [DIAGNOSTIC] Active EdDSA signing party not found, skipping message")
					continue
				}

				// 获取发送方的 PartyID
				fromPartyID, ok := m.nodeIDToPartyID[incomingMsg.fromNodeID]
				if !ok {
					log.Warn().
						Str("session_id", sessionID).
						Str("from_node_id", incomingMsg.fromNodeID).
						Msg("🔍 [DIAGNOSTIC] PartyID not found for from_node_id, message will be ignored")
					continue
				}

				// 使用 UpdateFromBytes 将消息注入到 party
				ok, tssErr := localParty.UpdateFromBytes(incomingMsg.msgBytes, fromPartyID, incomingMsg.isBroadcast)
				if !ok || tssErr != nil {
					log.Error().
						Interface("tss_error", tssErr).
						Str("session_id", sessionID).
						Str("from_node_id", incomingMsg.fromNodeID).
						Msg("🔍 [DIAGNOSTIC] Failed to update EdDSA signing party from message")
					// 继续处理其他消息，不返回错误
				}
			}
		}
	}()

	// 处理消息和结果（FROST 2 轮）
	timeout := time.NewTimer(opts.Timeout)
	defer timeout.Stop()

	for {
		select {
		case <-ctx.Done():
			m.mu.Lock()
			delete(m.activeEdDSASigning, sessionID)
			if ch, ok := m.incomingSigningMessages[sessionID]; ok {
				close(ch)
				delete(m.incomingSigningMessages, sessionID)
			}
			m.mu.Unlock()
			return nil, ctx.Err()
		case <-timeout.C:
			m.mu.Lock()
			delete(m.activeEdDSASigning, sessionID)
			if ch, ok := m.incomingSigningMessages[sessionID]; ok {
				close(ch)
				delete(m.incomingSigningMessages, sessionID)
			}
			m.mu.Unlock()
			return nil, errors.Errorf("%s signing timeout", opts.ProtocolName)
		case msg := <-outCh:
			// 路由消息到其他节点
			targetNodes := msg.GetTo()
			isBroadcast := len(targetNodes) == 0
			log.Info().
				Str("session_id", sessionID).
				Str("this_node_id", thisNodeID).
				Int("target_count", len(targetNodes)).
				Bool("is_broadcast", isBroadcast).
				Msg("🔍 [DIAGNOSTIC] Received message from EdDSA signing outCh, routing to other nodes")
			if m.messageRouter != nil {
				// 获取会话ID
				m.mu.RLock()
				currentSessionID := sessionID
				if mappedID, ok := m.sessionIDMap[sessionID]; ok {
					currentSessionID = mappedID
				}
				m.mu.RUnlock()

				if isBroadcast {
					// 广播消息：发送给所有其他节点
					m.mu.RLock()
					allPartyIDs := make([]*tss.PartyID, 0, len(m.nodeIDToPartyID))
					for nodeID, partyID := range m.nodeIDToPartyID {
						if nodeID != thisNodeID {
							allPartyIDs = append(allPartyIDs, partyID)
						}
					}
					m.mu.RUnlock()

					log.Info().
						Str("session_id", sessionID).
						Str("this_node_id", thisNodeID).
						Int("target_count", len(allPartyIDs)).
						Msg("🔍 [DIAGNOSTIC] Broadcasting EdDSA signing message to all nodes")

					for _, partyID := range allPartyIDs {
						targetNodeID, ok := m.partyIDToNodeID[partyID.Id]
						if !ok {
							log.Error().
								Str("party_id", partyID.Id).
								Str("session_id", sessionID).
								Msg("🔍 [DIAGNOSTIC] Failed to find nodeID for partyID in broadcast")
							continue
						}
						log.Debug().
							Str("session_id", sessionID).
							Str("target_node_id", targetNodeID).
							Str("party_id", partyID.Id).
							Msg("🔍 [DIAGNOSTIC] Broadcasting EdDSA signing message to node")
						if err := m.messageRouter(currentSessionID, targetNodeID, msg, true); err != nil {
							return nil, errors.Wrapf(err, "broadcast message to node %s", targetNodeID)
						}
					}
				} else {
					// 点对点消息：路由到指定目标节点
					for _, to := range targetNodes {
						targetNodeID, ok := m.getNodeID(to.Id)
						if !ok {
							return nil, errors.Errorf("party ID to node ID mapping not found: %s", to.Id)
						}
						log.Debug().
							Str("session_id", sessionID).
							Str("target_node_id", targetNodeID).
							Str("party_id", to.Id).
							Msg("🔍 [DIAGNOSTIC] Routing EdDSA signing message to target node")
						if err := m.messageRouter(currentSessionID, targetNodeID, msg, false); err != nil {
							return nil, errors.Wrapf(err, "route message to node %s", targetNodeID)
						}
					}
				}
			} else {
				log.Warn().
					Str("session_id", sessionID).
					Msg("🔍 [DIAGNOSTIC] Message router is nil, cannot route EdDSA signing message")
			}
		case sigData := <-endCh:
			m.mu.Lock()
			delete(m.activeEdDSASigning, sessionID)
			if ch, ok := m.incomingSigningMessages[sessionID]; ok {
				close(ch)
				delete(m.incomingSigningMessages, sessionID)
			}
			m.mu.Unlock()
			if sigData == nil {
				return nil, errors.Errorf("%s signing returned nil signature data", opts.ProtocolName)
			}
			return sigData, nil
		case err := <-errCh:
			m.mu.Lock()
			delete(m.activeEdDSASigning, sessionID)
			if ch, ok := m.incomingSigningMessages[sessionID]; ok {
				close(ch)
				delete(m.incomingSigningMessages, sessionID)
			}
			m.mu.Unlock()
			if opts.EnableIdentifiableAbort && err.Culprits() != nil {
				return nil, errors.Wrapf(err, "%s signing error (identifiable abort: %v)", opts.ProtocolName, err.Culprits())
			}
			return nil, errors.Wrapf(err, "%s signing error", opts.ProtocolName)
		}
	}
}
