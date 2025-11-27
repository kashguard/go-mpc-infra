package node

import (
	"context"
	"math/rand"
	"time"

	"github.com/kashguard/go-mpc-wallet/internal/mpc/storage"
	"github.com/pkg/errors"
)

// Discovery 节点发现
type Discovery struct {
	manager *Manager
}

// NewDiscovery 创建节点发现器
func NewDiscovery(manager *Manager) *Discovery {
	return &Discovery{
		manager: manager,
	}
}

// DiscoverNodes 发现节点
func (d *Discovery) DiscoverNodes(ctx context.Context, nodeType NodeType, status NodeStatus, limit int) ([]*Node, error) {
	filter := &storage.NodeFilter{
		NodeType: string(nodeType),
		Status:   string(status),
		Limit:    limit,
		Offset:   0,
	}

	nodes, err := d.manager.ListNodes(ctx, filter)
	if err != nil {
		return nil, errors.Wrap(err, "failed to discover nodes")
	}

	return nodes, nil
}

// SelectParticipatingNodes 选择参与节点（用于签名）
func (d *Discovery) SelectParticipatingNodes(ctx context.Context, threshold int, totalNodes int) ([]*Node, error) {
	// 发现所有活跃的Participant节点
	participants, err := d.DiscoverNodes(ctx, NodeTypeParticipant, NodeStatusActive, totalNodes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to discover participants")
	}

	if len(participants) < threshold {
		return nil, errors.Errorf("insufficient active nodes: need %d, have %d", threshold, len(participants))
	}

	// 随机选择达到阈值的节点
	selected := selectRandomNodes(participants, threshold)

	return selected, nil
}

// selectRandomNodes 随机选择节点
func selectRandomNodes(nodes []*Node, count int) []*Node {
	if count >= len(nodes) {
		return nodes
	}

	// 创建副本避免修改原数组
	copyNodes := make([]*Node, len(nodes))
	copy(copyNodes, nodes)

	// 随机打乱
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	r.Shuffle(len(copyNodes), func(i, j int) {
		copyNodes[i], copyNodes[j] = copyNodes[j], copyNodes[i]
	})

	return copyNodes[:count]
}

// CheckNodeAvailability 检查节点可用性
func (d *Discovery) CheckNodeAvailability(ctx context.Context, nodeID string) (bool, error) {
	node, err := d.manager.GetNode(ctx, nodeID)
	if err != nil {
		return false, errors.Wrap(err, "failed to get node")
	}

	if node.Status != string(NodeStatusActive) {
		return false, nil
	}

	// 检查心跳
	if node.LastHeartbeat != nil {
		timeSinceHeartbeat := time.Since(*node.LastHeartbeat)
		if timeSinceHeartbeat > 5*time.Minute {
			return false, nil // 心跳超时
		}
	}

	return true, nil
}
