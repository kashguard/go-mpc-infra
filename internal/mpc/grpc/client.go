package grpc

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/kashguard/go-mpc-wallet/internal/config"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/node"
	pb "github.com/kashguard/go-mpc-wallet/internal/pb/mpc/v1"
	"github.com/kashguard/tss-lib/tss"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// GRPCClient gRPC客户端，用于节点间通信
type GRPCClient struct {
	mu            sync.RWMutex
	conns         map[string]*grpc.ClientConn
	clients       map[string]pb.MPCNodeClient
	cfg           *ClientConfig
	nodeManager   *node.Manager
	nodeDiscovery *node.Discovery // 用于从 Consul 发现节点信息
	thisNodeID    string          // 当前节点ID（用于标识消息发送方）
}

// ClientConfig gRPC客户端配置
type ClientConfig struct {
	TLSEnabled    bool
	TLSCertFile   string
	TLSKeyFile    string
	TLSCACertFile string
	Timeout       time.Duration
	KeepAlive     time.Duration
}

// NewGRPCClient 创建gRPC客户端
func NewGRPCClient(cfg config.Server, nodeManager *node.Manager) (*GRPCClient, error) {
	// DKG 协议可能需要较长时间（几分钟），设置更长的超时时间
	// KeepAlive Timeout 设置为 10 分钟，确保长运行的 RPC 调用不会被中断
	clientCfg := &ClientConfig{
		TLSEnabled: cfg.MPC.TLSEnabled,
		Timeout:    10 * time.Minute, // 增加到 10 分钟
		KeepAlive:  10 * time.Minute, // 增加到 10 分钟
	}

	thisNodeID := cfg.MPC.NodeID
	if thisNodeID == "" {
		thisNodeID = "default-node"
	}

	return &GRPCClient{
		conns:         make(map[string]*grpc.ClientConn),
		clients:       make(map[string]pb.MPCNodeClient),
		cfg:           clientCfg,
		nodeManager:   nodeManager,
		nodeDiscovery: nil, // 稍后通过 SetNodeDiscovery 设置
		thisNodeID:    thisNodeID,
	}, nil
}

// SetNodeDiscovery 设置节点发现器（用于从 Consul 获取节点信息）
func (c *GRPCClient) SetNodeDiscovery(discovery *node.Discovery) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nodeDiscovery = discovery
}

// getOrCreateConnection 获取或创建到指定节点的连接
func (c *GRPCClient) getOrCreateConnection(ctx context.Context, nodeID string) (pb.MPCNodeClient, error) {
	c.mu.RLock()
	client, ok := c.clients[nodeID]
	c.mu.RUnlock()

	if ok {
		return client, nil
	}

	// 获取节点信息
	// 首先尝试从数据库获取
	var nodeInfo *node.Node
	var err error
	nodeInfo, err = c.nodeManager.GetNode(ctx, nodeID)
	if err != nil {
		// 如果从数据库获取失败，尝试从 Consul 服务发现中获取
		if c.nodeDiscovery != nil {
			// 从 Consul 发现节点（尝试发现所有类型的节点）
			// 注意：这里我们需要知道节点类型，但暂时尝试 participant 和 coordinator
			for _, nodeType := range []node.NodeType{node.NodeTypeParticipant, node.NodeTypeCoordinator} {
				// ✅ 使用较小的 limit（与典型参与者数量匹配），并忽略数量不足的错误
				nodes, discoverErr := c.nodeDiscovery.DiscoverNodes(ctx, nodeType, node.NodeStatusActive, 3)
				// 即使返回错误（节点数不足），也可能返回了部分节点，继续查找
				if discoverErr != nil {
					// 忽略数量不足的错误，只要有节点就继续
					if len(nodes) == 0 {
						continue
					}
				}

				// 查找匹配的节点
				for _, n := range nodes {
					if n.NodeID == nodeID {
						nodeInfo = n
						err = nil
						break
					}
				}
				if err == nil {
					break
				}
			}
		}

		// 如果仍然失败，返回错误
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get node info for %s (not found in database or Consul)", nodeID)
		}
	}

	// 创建连接
	c.mu.Lock()
	defer c.mu.Unlock()

	// 双重检查
	if client, ok := c.clients[nodeID]; ok {
		return client, nil
	}

	// 配置连接选项
	var opts []grpc.DialOption

	// TLS配置
	if c.cfg.TLSEnabled {
		creds, err := credentials.NewClientTLSFromFile(c.cfg.TLSCACertFile, "")
		if err != nil {
			return nil, errors.Wrap(err, "failed to load TLS credentials")
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// KeepAlive配置
	opts = append(opts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                c.cfg.KeepAlive,
		Timeout:             c.cfg.Timeout,
		PermitWithoutStream: true,
	}))

	// 建立连接
	log.Debug().Str("node_id", nodeID).Str("endpoint", nodeInfo.Endpoint).Msg("Dialing gRPC node")
	conn, err := grpc.NewClient(nodeInfo.Endpoint, opts...)
	if err != nil {
		log.Error().Err(err).Str("node_id", nodeID).Str("endpoint", nodeInfo.Endpoint).Msg("Failed to connect to gRPC node")
		return nil, errors.Wrapf(err, "failed to connect to node %s at %s", nodeID, nodeInfo.Endpoint)
	}
	log.Debug().Str("node_id", nodeID).Str("endpoint", nodeInfo.Endpoint).Msg("Successfully connected to gRPC node")

	// 创建客户端
	client = pb.NewMPCNodeClient(conn)

	// 保存连接和客户端
	c.conns[nodeID] = conn
	c.clients[nodeID] = client

	return client, nil
}

// SendStartDKG 调用参与者的 StartDKG RPC
func (c *GRPCClient) SendStartDKG(ctx context.Context, nodeID string, req *pb.StartDKGRequest) (*pb.StartDKGResponse, error) {
	log.Debug().
		Str("node_id", nodeID).
		Str("key_id", req.KeyId).
		Msg("Sending StartDKG RPC to participant")

	client, err := c.getOrCreateConnection(ctx, nodeID)
	if err != nil {
		log.Error().Err(err).Str("node_id", nodeID).Msg("Failed to get gRPC connection")
		return nil, errors.Wrapf(err, "failed to get connection to node %s", nodeID)
	}

	log.Debug().
		Str("node_id", nodeID).
		Str("key_id", req.KeyId).
		Msg("Calling StartDKG RPC")

	resp, err := client.StartDKG(ctx, req)
	if err != nil {
		log.Error().
			Err(err).
			Str("node_id", nodeID).
			Str("key_id", req.KeyId).
			Msg("StartDKG RPC call failed")
		return nil, err
	}

	log.Debug().
		Str("node_id", nodeID).
		Str("key_id", req.KeyId).
		Bool("started", resp.Started).
		Str("message", resp.Message).
		Msg("StartDKG RPC call succeeded")

	return resp, nil
}

// SendStartSign 调用参与者的 StartSign RPC
func (c *GRPCClient) SendStartSign(ctx context.Context, nodeID string, req *pb.StartSignRequest) (*pb.StartSignResponse, error) {
	log.Debug().
		Str("node_id", nodeID).
		Str("key_id", req.KeyId).
		Str("session_id", req.SessionId).
		Msg("Sending StartSign RPC to participant")

	client, err := c.getOrCreateConnection(ctx, nodeID)
	if err != nil {
		log.Error().Err(err).Str("node_id", nodeID).Msg("Failed to get gRPC connection")
		return nil, errors.Wrapf(err, "failed to get connection to node %s", nodeID)
	}

	log.Debug().
		Str("node_id", nodeID).
		Str("key_id", req.KeyId).
		Str("session_id", req.SessionId).
		Msg("Calling StartSign RPC")

	resp, err := client.StartSign(ctx, req)
	if err != nil {
		log.Error().
			Err(err).
			Str("node_id", nodeID).
			Str("key_id", req.KeyId).
			Str("session_id", req.SessionId).
			Msg("StartSign RPC call failed")
		return nil, err
	}

	log.Debug().
		Str("node_id", nodeID).
		Str("key_id", req.KeyId).
		Str("session_id", req.SessionId).
		Bool("started", resp.Started).
		Str("message", resp.Message).
		Msg("StartSign RPC call succeeded")

	return resp, nil
}

// SendSigningMessage 发送签名协议消息到目标节点
func (c *GRPCClient) SendSigningMessage(ctx context.Context, nodeID string, msg tss.Message, sessionID string) error {
	// 防止节点向自己发送消息
	if nodeID == c.thisNodeID {
		log.Warn().
			Str("session_id", sessionID).
			Str("node_id", nodeID).
			Str("this_node_id", c.thisNodeID).
			Msg("Attempted to send signing message to self, skipping")
		return nil // 不返回错误，只是跳过
	}

	client, err := c.getOrCreateConnection(ctx, nodeID)
	if err != nil {
		return errors.Wrapf(err, "failed to get connection to node %s", nodeID)
	}

	// 序列化tss-lib消息
	// WireBytes()返回 (wireBytes []byte, routing *MessageRouting, err error)
	msgBytes, routing, err := msg.WireBytes()
	if err != nil {
		return errors.Wrap(err, "failed to serialize tss message")
	}

	// 确定轮次（tss-lib的MessageRouting可能不包含Round字段，使用0作为默认值）
	// 实际轮次信息可以从消息内容中提取，这里简化处理
	round := int32(0)
	isBroadcast := len(msg.GetTo()) == 0
	if isBroadcast {
		round = -1
	}

	// ✅ 详细日志：记录消息发送详情
	msgType := fmt.Sprintf("%T", msg)
	log.Info().
		Str("session_id", sessionID).
		Str("this_node_id", c.thisNodeID).
		Str("target_node_id", nodeID).
		Str("message_type", msgType).
		Int32("round", round).
		Bool("is_broadcast", isBroadcast).
		Int("msg_bytes_len", len(msgBytes)).
		Int("target_count", len(msg.GetTo())).
		Interface("routing", routing).
		Msg("🔍 [DIAGNOSTIC] Sending signing message via gRPC")

	// 使用SubmitSignatureShare发送消息
	// 注意：NodeId应该表示发送方节点ID，而不是目标节点ID
	shareReq := &pb.ShareRequest{
		SessionId: sessionID,    // 使用传入的会话ID
		NodeId:    c.thisNodeID, // 发送方节点ID（当前节点）
		ShareData: msgBytes,
		Round:     round,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	resp, err := client.SubmitSignatureShare(ctx, shareReq)
	if err != nil {
		log.Error().
			Err(err).
			Str("session_id", sessionID).
			Str("this_node_id", c.thisNodeID).
			Str("target_node_id", nodeID).
			Msg("🔍 [DIAGNOSTIC] Failed to send signing message via gRPC")
		return errors.Wrapf(err, "failed to send signing message to node %s", nodeID)
	}

	log.Info().
		Str("session_id", sessionID).
		Str("this_node_id", c.thisNodeID).
		Str("target_node_id", nodeID).
		Bool("accepted", resp.Accepted).
		Int32("next_round", resp.NextRound).
		Str("message", resp.Message).
		Msg("🔍 [DIAGNOSTIC] Signing message sent successfully via gRPC")

	return nil
}

// SendKeygenMessage 发送DKG协议消息到目标节点
func (c *GRPCClient) SendKeygenMessage(ctx context.Context, nodeID string, msg tss.Message, sessionID string, isBroadcast bool) error {
	// 防止节点向自己发送消息
	if nodeID == c.thisNodeID {
		log.Warn().
			Str("session_id", sessionID).
			Str("node_id", nodeID).
			Str("this_node_id", c.thisNodeID).
			Msg("Attempted to send DKG message to self, skipping")
		return nil // 不返回错误，只是跳过
	}

	client, err := c.getOrCreateConnection(ctx, nodeID)
	if err != nil {
		return errors.Wrapf(err, "failed to get connection to node %s", nodeID)
	}

	// 序列化tss-lib消息
	msgBytes, _, err := msg.WireBytes()
	if err != nil {
		return errors.Wrap(err, "failed to serialize tss message")
	}

	// 确定轮次（tss-lib的MessageRouting可能不包含Round字段，使用0作为默认值）
	round := int32(0)
	// 如果 tss 消息没有目标（broadcast）或上层标记为广播，则使用 -1
	if len(msg.GetTo()) == 0 || isBroadcast {
		round = -1
	}

	log.Debug().
		Str("session_id", sessionID).
		Str("target_node_id", nodeID).
		Int("to_count", len(msg.GetTo())).
		Bool("is_broadcast_flag", isBroadcast).
		Int32("round_set", round).
		Msg("Sending DKG ShareRequest via gRPC")

	// DKG消息也通过SubmitSignatureShare发送（使用相同的协议）
	// 服务端会根据会话类型判断是DKG还是签名消息
	// 注意：NodeId应该表示发送方节点ID，而不是目标节点ID
	// 目标节点ID已经通过gRPC调用的目标地址确定了
	shareReq := &pb.ShareRequest{
		SessionId: sessionID,    // 使用keyID作为会话ID
		NodeId:    c.thisNodeID, // 发送方节点ID（当前节点）
		ShareData: msgBytes,
		Round:     round,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// 发送消息
	resp, err := client.SubmitSignatureShare(ctx, shareReq)
	if err != nil {
		return errors.Wrapf(err, "failed to send keygen message to node %s (sessionID: %s)", nodeID, sessionID)
	}

	if !resp.Accepted {
		return errors.Errorf("node %s rejected keygen message: %s", nodeID, resp.Message)
	}

	// 这是一个非常详细的日志，仅在调试时启用
	// fmt.Printf("Successfully sent keygen message to %s (round: %d, len: %d)\n", nodeID, round, len(msgBytes))

	return nil
}

// SendDKGStartNotification 发送 DKG 启动通知给 participant
func (c *GRPCClient) SendDKGStartNotification(ctx context.Context, nodeID string, sessionID string) error {
	client, err := c.getOrCreateConnection(ctx, nodeID)
	if err != nil {
		return errors.Wrapf(err, "failed to get connection to node %s", nodeID)
	}

	// 发送特殊的 "DKG_START" 消息
	shareReq := &pb.ShareRequest{
		SessionId: sessionID,
		NodeId:    nodeID,
		ShareData: []byte("DKG_START"), // 特殊标记，participant 会识别并启动 DKG
		Round:     0,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	_, err = client.SubmitSignatureShare(ctx, shareReq)
	if err != nil {
		return errors.Wrapf(err, "failed to send DKG start notification to node %s (sessionID: %s)", nodeID, sessionID)
	}

	return nil
}

// CloseConnection 关闭到指定节点的连接
func (c *GRPCClient) CloseConnection(nodeID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if conn, ok := c.conns[nodeID]; ok {
		if err := conn.Close(); err != nil {
			return errors.Wrapf(err, "failed to close connection to node %s", nodeID)
		}
		delete(c.conns, nodeID)
		delete(c.clients, nodeID)
	}

	return nil
}

// Close 关闭所有连接
func (c *GRPCClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var errs []error
	for nodeID, conn := range c.conns {
		if err := conn.Close(); err != nil {
			errs = append(errs, errors.Wrapf(err, "failed to close connection to node %s", nodeID))
		}
	}

	c.conns = make(map[string]*grpc.ClientConn)
	c.clients = make(map[string]pb.MPCNodeClient)

	if len(errs) > 0 {
		return errors.Errorf("errors closing connections: %v", errs)
	}

	return nil
}
