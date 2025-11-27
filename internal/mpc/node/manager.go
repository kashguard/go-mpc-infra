package node

import (
	"context"
	"time"

	"github.com/kashguard/go-mpc-wallet/internal/mpc/storage"
	"github.com/pkg/errors"
)

// Manager 节点管理器
type Manager struct {
	metadataStore     storage.MetadataStore
	heartbeatInterval time.Duration
}

// NewManager 创建节点管理器
func NewManager(metadataStore storage.MetadataStore, heartbeatInterval time.Duration) *Manager {
	return &Manager{
		metadataStore:     metadataStore,
		heartbeatInterval: heartbeatInterval,
	}
}

// RegisterNode 注册节点
func (m *Manager) RegisterNode(ctx context.Context, node *Node) error {
	nodeInfo := &storage.NodeInfo{
		NodeID:       node.NodeID,
		NodeType:     node.NodeType,
		Endpoint:     node.Endpoint,
		PublicKey:    node.PublicKey,
		Status:       string(node.Status),
		Capabilities: node.Capabilities,
		Metadata:     node.Metadata,
		RegisteredAt: node.RegisteredAt,
	}

	if err := m.metadataStore.SaveNode(ctx, nodeInfo); err != nil {
		return errors.Wrap(err, "failed to register node")
	}

	return nil
}

// GetNode 获取节点信息
func (m *Manager) GetNode(ctx context.Context, nodeID string) (*Node, error) {
	nodeInfo, err := m.metadataStore.GetNode(ctx, nodeID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get node")
	}

	return &Node{
		NodeID:        nodeInfo.NodeID,
		NodeType:      nodeInfo.NodeType,
		Endpoint:      nodeInfo.Endpoint,
		PublicKey:     nodeInfo.PublicKey,
		Status:        nodeInfo.Status,
		Capabilities:  nodeInfo.Capabilities,
		Metadata:      nodeInfo.Metadata,
		RegisteredAt:  nodeInfo.RegisteredAt,
		LastHeartbeat: nodeInfo.LastHeartbeat,
	}, nil
}

// ListNodes 列出节点
func (m *Manager) ListNodes(ctx context.Context, filter *storage.NodeFilter) ([]*Node, error) {
	nodeInfos, err := m.metadataStore.ListNodes(ctx, filter)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list nodes")
	}

	nodes := make([]*Node, len(nodeInfos))
	for i, nodeInfo := range nodeInfos {
		nodes[i] = &Node{
			NodeID:        nodeInfo.NodeID,
			NodeType:      nodeInfo.NodeType,
			Endpoint:      nodeInfo.Endpoint,
			PublicKey:     nodeInfo.PublicKey,
			Status:        nodeInfo.Status,
			Capabilities:  nodeInfo.Capabilities,
			Metadata:      nodeInfo.Metadata,
			RegisteredAt:  nodeInfo.RegisteredAt,
			LastHeartbeat: nodeInfo.LastHeartbeat,
		}
	}

	return nodes, nil
}

// UpdateNodeStatus 更新节点状态
func (m *Manager) UpdateNodeStatus(ctx context.Context, nodeID string, status NodeStatus) error {
	node, err := m.GetNode(ctx, nodeID)
	if err != nil {
		return errors.Wrap(err, "failed to get node")
	}

	node.Status = string(status)
	nodeInfo := &storage.NodeInfo{
		NodeID:        node.NodeID,
		NodeType:      node.NodeType,
		Endpoint:      node.Endpoint,
		PublicKey:     node.PublicKey,
		Status:        node.Status,
		Capabilities:  node.Capabilities,
		Metadata:      node.Metadata,
		RegisteredAt:  node.RegisteredAt,
		LastHeartbeat: node.LastHeartbeat,
	}

	if err := m.metadataStore.UpdateNode(ctx, nodeInfo); err != nil {
		return errors.Wrap(err, "failed to update node status")
	}

	return nil
}

// UpdateHeartbeat 更新节点心跳
func (m *Manager) UpdateHeartbeat(ctx context.Context, nodeID string) error {
	if err := m.metadataStore.UpdateNodeHeartbeat(ctx, nodeID); err != nil {
		return errors.Wrap(err, "failed to update heartbeat")
	}
	return nil
}

// HealthCheck 健康检查
func (m *Manager) HealthCheck(ctx context.Context, nodeID string) (*HealthCheck, error) {
	node, err := m.GetNode(ctx, nodeID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get node")
	}

	checks := make(map[string]string)
	metrics := make(map[string]float64)

	// 检查节点状态
	if node.Status == string(NodeStatusActive) {
		checks["status"] = "ok"
	} else {
		checks["status"] = "faulty"
	}

	// 检查心跳
	if node.LastHeartbeat != nil {
		timeSinceHeartbeat := time.Since(*node.LastHeartbeat)
		if timeSinceHeartbeat < m.heartbeatInterval*2 {
			checks["heartbeat"] = "ok"
		} else {
			checks["heartbeat"] = "stale"
		}
		metrics["heartbeat_age_seconds"] = timeSinceHeartbeat.Seconds()
	} else {
		checks["heartbeat"] = "missing"
	}

	// 确定整体状态
	overallStatus := "healthy"
	if checks["status"] != "ok" || checks["heartbeat"] != "ok" {
		overallStatus = "unhealthy"
	}

	return &HealthCheck{
		NodeID:    nodeID,
		Status:    overallStatus,
		Timestamp: time.Now(),
		Checks:    checks,
		Metrics:   metrics,
	}, nil
}
