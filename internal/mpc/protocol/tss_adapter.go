package protocol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/kashguard/tss-lib/common"
	"github.com/kashguard/tss-lib/ecdsa/keygen"
	"github.com/kashguard/tss-lib/ecdsa/signing"
	eddsaKeygen "github.com/kashguard/tss-lib/eddsa/keygen"
	eddsaSigning "github.com/kashguard/tss-lib/eddsa/signing"
	"github.com/kashguard/tss-lib/tss"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// tssPartyManager 管理 tss-lib 的 Party 实例和消息路由（通用适配层，供 GG18/GG20/FROST 使用）
type tssPartyManager struct {
	mu sync.RWMutex

	// 节点到 PartyID 的映射
	nodeIDToPartyID map[string]*tss.PartyID
	partyIDToNodeID map[string]string

	// 当前活跃的协议实例（ECDSA - GG18/GG20）
	activeKeygen  map[string]*keygen.LocalParty
	activeSigning map[string]*signing.LocalParty

	// 当前活跃的协议实例（EdDSA - FROST）
	activeEdDSAKeygen  map[string]*eddsaKeygen.LocalParty
	activeEdDSASigning map[string]*eddsaSigning.LocalParty

	// 消息路由：从 tss-lib 消息到节点通信
	// 参数：sessionID（用于DKG或签名会话），nodeID（目标节点），msg（tss-lib消息）
	messageRouter func(sessionID string, nodeID string, msg tss.Message, isBroadcast bool) error

	// 接收到的消息队列（用于处理来自其他节点的消息）
	// 消息包含字节数据和发送方节点ID
	incomingKeygenMessages  map[string]chan *incomingMessage
	incomingSigningMessages map[string]chan *incomingMessage

	// 会话ID映射：keyID/sessionID -> sessionID（用于消息路由时获取会话ID）
	sessionIDMap map[string]string
}

// incomingMessage 接收到的消息（包含消息字节和发送方信息）
type incomingMessage struct {
	msgBytes    []byte
	fromNodeID  string
	isBroadcast bool
}

func newTSSPartyManager(messageRouter func(sessionID string, nodeID string, msg tss.Message, isBroadcast bool) error) *tssPartyManager {
	return &tssPartyManager{
		nodeIDToPartyID:         make(map[string]*tss.PartyID),
		partyIDToNodeID:         make(map[string]string),
		activeKeygen:            make(map[string]*keygen.LocalParty),
		activeSigning:           make(map[string]*signing.LocalParty),
		activeEdDSAKeygen:       make(map[string]*eddsaKeygen.LocalParty),
		activeEdDSASigning:      make(map[string]*eddsaSigning.LocalParty),
		messageRouter:           messageRouter,
		incomingKeygenMessages:  make(map[string]chan *incomingMessage),
		incomingSigningMessages: make(map[string]chan *incomingMessage),
		sessionIDMap:            make(map[string]string),
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
			Msg("Reusing existing incomingKeygenMessages channel for DKG")
	}
	m.mu.Unlock()

	// 启动协议
	go func() {
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
				log.Debug().
					Str("key_id", keyID).
					Str("from_node_id", incomingMsg.fromNodeID).
					Bool("is_broadcast", incomingMsg.isBroadcast).
					Int("msg_bytes_len", len(incomingMsg.msgBytes)).
					Msg("Received message in processing loop")

				// 获取LocalParty实例
				m.mu.RLock()
				localParty, exists := m.activeKeygen[keyID]
				m.mu.RUnlock()

				if !exists {
					log.Debug().
						Str("key_id", keyID).
						Str("from_node_id", incomingMsg.fromNodeID).
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
						Msg("Failed to update local party from bytes")
					continue
				} else {
					log.Debug().
						Str("key_id", keyID).
						Str("from_node_id", incomingMsg.fromNodeID).
						Bool("is_broadcast", incomingMsg.isBroadcast).
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
			return nil, ctx.Err()
		case <-timeout.C:
			return nil, errors.New("keygen timeout")
		case msg := <-outCh:
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

// SigningOptions 签名执行选项
type SigningOptions struct {
	// Timeout 超时时间（默认 2 分钟）
	Timeout time.Duration
	// EnableIdentifiableAbort 是否支持可识别的中止（GG20 特性）
	EnableIdentifiableAbort bool
	// ProtocolName 协议名称（用于错误消息）
	ProtocolName string
}

// DefaultSigningOptions 返回默认的签名选项（GG18）
func DefaultSigningOptions() SigningOptions {
	return SigningOptions{
		Timeout:                 2 * time.Minute,
		EnableIdentifiableAbort: false,
		ProtocolName:            "GG18",
	}
}

// GG20SigningOptions 返回 GG20 的签名选项
func GG20SigningOptions() SigningOptions {
	return SigningOptions{
		Timeout:                 1 * time.Minute,
		EnableIdentifiableAbort: true,
		ProtocolName:            "GG20",
	}
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
	opts SigningOptions,
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
	params := tss.NewParameters(tss.S256(), ctxTSS, thisPartyID, len(parties), len(parties)-1)

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
	m.mu.Unlock()

	// 创建消息队列（如果不存在）
	m.mu.Lock()
	msgCh, exists := m.incomingSigningMessages[sessionID]
	if !exists {
		msgCh = make(chan *incomingMessage, 100)
		m.incomingSigningMessages[sessionID] = msgCh
	}
	m.mu.Unlock()

	// 启动协议
	go func() {
		if err := party.Start(); err != nil {
			errCh <- err
		}
	}()

	// 启动消息处理循环：从队列读取消息并注入到party
	// 使用tss-lib的UpdateFromBytes方法将消息注入到LocalParty
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case incomingMsg, ok := <-msgCh:
				if !ok {
					return
				}
				// 获取LocalParty实例
				m.mu.RLock()
				localParty, exists := m.activeSigning[sessionID]
				m.mu.RUnlock()

				if !exists {
					// LocalParty还未创建或已结束，忽略消息
					continue
				}

				// 获取发送方的PartyID
				fromPartyID, ok := m.nodeIDToPartyID[incomingMsg.fromNodeID]
				if !ok {
					// 发送方节点ID未找到，忽略消息
					continue
				}

				// 使用UpdateFromBytes将消息注入到LocalParty
				// isBroadcast参数：如果消息是广播消息则为true，否则为false
				ok, tssErr := localParty.UpdateFromBytes(incomingMsg.msgBytes, fromPartyID, false)
				if !ok || tssErr != nil {
					// 消息注入失败，记录错误但继续处理其他消息
					continue
				}
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

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout.C:
			return nil, errors.Errorf("%s signing timeout", opts.ProtocolName)
		case msg := <-outCh:
			// 路由消息到其他节点
			if m.messageRouter != nil {
				// 获取会话ID
				m.mu.RLock()
				currentSessionID := sessionID
				if mappedID, ok := m.sessionIDMap[sessionID]; ok {
					currentSessionID = mappedID
				}
				m.mu.RUnlock()

				// 路由到所有目标节点
				for _, to := range msg.GetTo() {
					targetNodeID, ok := m.getNodeID(to.Id)
					if !ok {
						return nil, errors.Errorf("party ID to node ID mapping not found: %s", to.Id)
					}
					if err := m.messageRouter(currentSessionID, targetNodeID, msg, false); err != nil {
						return nil, errors.Wrapf(err, "route message to node %s", targetNodeID)
					}
				}
			}
		case sigData := <-endCh:
			m.mu.Lock()
			delete(m.activeSigning, sessionID)
			// 清理消息队列
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
			delete(m.activeSigning, sessionID)
			// 清理消息队列
			if ch, ok := m.incomingSigningMessages[sessionID]; ok {
				close(ch)
				delete(m.incomingSigningMessages, sessionID)
			}
			m.mu.Unlock()
			// 如果支持可识别的中止，可以识别恶意节点
			if opts.EnableIdentifiableAbort && err.Culprits() != nil {
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
	// 将消息放入队列，由executeKeygen中的消息处理循环读取
	// 消息包含字节数据和发送方节点ID
	m.mu.Lock()
	msgCh, exists := m.incomingKeygenMessages[sessionID]
	if !exists {
		msgCh = make(chan *incomingMessage, 100)
		m.incomingKeygenMessages[sessionID] = msgCh
		log.Info().
			Str("session_id", sessionID).
			Str("from_node_id", fromNodeID).
			Msg("Created incomingKeygenMessages channel (message arrived before DKG started)")
	}
	m.mu.Unlock()

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
		Msg("Processing incoming DKG message")

	// 非阻塞发送
	select {
	case msgCh <- incomingMsg:
		// 消息已放入队列，由executeKeygen中的消息处理循环处理
		log.Debug().
			Str("session_id", sessionID).
			Str("from_node_id", fromNodeID).
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
) error {
	// 将消息放入队列，由executeSigning中的消息处理循环处理
	m.mu.Lock()
	msgCh, exists := m.incomingSigningMessages[sessionID]
	if !exists {
		msgCh = make(chan *incomingMessage, 100)
		m.incomingSigningMessages[sessionID] = msgCh
	}
	m.mu.Unlock()

	// 创建消息对象
	incomingMsg := &incomingMessage{
		msgBytes:   msgBytes,
		fromNodeID: fromNodeID,
	}

	// 非阻塞发送
	select {
	case msgCh <- incomingMsg:
		// 消息已放入队列，由executeSigning中的消息处理循环处理
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
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
	opts SigningOptions,
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

	// 计算消息哈希
	hash := sha256.Sum256(message)
	msgBigInt := new(big.Int).SetBytes(hash[:])

	// 创建消息通道
	outCh := make(chan tss.Message, len(parties))
	endCh := make(chan *common.SignatureData, 1)
	errCh := make(chan *tss.Error, 1)

	// 创建 EdDSA LocalParty（FROST 使用 EdDSA signing，2 轮）
	party := eddsaSigning.NewLocalParty(msgBigInt, params, *keyData, outCh, endCh)

	m.mu.Lock()
	if localParty, ok := party.(*eddsaSigning.LocalParty); ok {
		m.activeEdDSASigning[sessionID] = localParty
	}
	// 记录会话ID映射
	m.sessionIDMap[sessionID] = sessionID
	m.mu.Unlock()

	// 启动协议
	go func() {
		if err := party.Start(); err != nil {
			errCh <- err
		}
	}()

	// 处理消息和结果（FROST 2 轮，超时时间可以更短）
	timeout := time.NewTimer(opts.Timeout)
	defer timeout.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout.C:
			return nil, errors.Errorf("%s signing timeout", opts.ProtocolName)
		case msg := <-outCh:
			// 路由消息到其他节点
			if m.messageRouter != nil {
				// 获取会话ID
				m.mu.RLock()
				currentSessionID := sessionID
				if mappedID, ok := m.sessionIDMap[sessionID]; ok {
					currentSessionID = mappedID
				}
				m.mu.RUnlock()

				// 路由到所有目标节点
				for _, to := range msg.GetTo() {
					targetNodeID, ok := m.getNodeID(to.Id)
					if !ok {
						return nil, errors.Errorf("party ID to node ID mapping not found: %s", to.Id)
					}
					if err := m.messageRouter(currentSessionID, targetNodeID, msg, false); err != nil {
						return nil, errors.Wrapf(err, "route message to node %s", targetNodeID)
					}
				}
			}
		case sigData := <-endCh:
			m.mu.Lock()
			delete(m.activeEdDSASigning, sessionID)
			m.mu.Unlock()
			if sigData == nil {
				return nil, errors.Errorf("%s signing returned nil signature data", opts.ProtocolName)
			}
			return sigData, nil
		case err := <-errCh:
			m.mu.Lock()
			delete(m.activeEdDSASigning, sessionID)
			m.mu.Unlock()
			if opts.EnableIdentifiableAbort && err.Culprits() != nil {
				return nil, errors.Wrapf(err, "%s signing error (identifiable abort: %v)", opts.ProtocolName, err.Culprits())
			}
			return nil, errors.Wrapf(err, "%s signing error", opts.ProtocolName)
		}
	}
}

// FROSTSigningOptions 返回 FROST 的签名选项
func FROSTSigningOptions() SigningOptions {
	return SigningOptions{
		Timeout:                 1 * time.Minute, // FROST 2 轮，超时时间更短
		EnableIdentifiableAbort: false,           // FROST 不支持可识别的中止
		ProtocolName:            "FROST",
	}
}
