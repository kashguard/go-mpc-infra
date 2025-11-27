package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/pkg/errors"
)

// Registry 节点注册器
type Registry struct {
	manager *Manager
}

// NewRegistry 创建节点注册器
func NewRegistry(manager *Manager) *Registry {
	return &Registry{
		manager: manager,
	}
}

// RegisterCoordinator 注册Coordinator节点
func (r *Registry) RegisterCoordinator(ctx context.Context, endpoint string, publicKey string) (*Node, error) {
	nodeID := generateNodeID("coordinator")

	node := &Node{
		NodeID:       nodeID,
		NodeType:     string(NodeTypeCoordinator),
		Endpoint:     endpoint,
		PublicKey:    publicKey,
		Status:       string(NodeStatusActive),
		Capabilities: []string{"gg18", "gg20"},
		Metadata:     make(map[string]interface{}),
		RegisteredAt: time.Now(),
	}

	if err := r.manager.RegisterNode(ctx, node); err != nil {
		return nil, errors.Wrap(err, "failed to register coordinator")
	}

	return node, nil
}

// RegisterParticipant 注册Participant节点
func (r *Registry) RegisterParticipant(ctx context.Context, endpoint string, publicKey string, capabilities []string) (*Node, error) {
	nodeID := generateNodeID("participant")

	node := &Node{
		NodeID:       nodeID,
		NodeType:     string(NodeTypeParticipant),
		Endpoint:     endpoint,
		PublicKey:    publicKey,
		Status:       string(NodeStatusActive),
		Capabilities: capabilities,
		Metadata:     make(map[string]interface{}),
		RegisteredAt: time.Now(),
	}

	if err := r.manager.RegisterNode(ctx, node); err != nil {
		return nil, errors.Wrap(err, "failed to register participant")
	}

	return node, nil
}

// generateNodeID 生成节点ID
func generateNodeID(prefix string) string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return prefix + "-" + hex.EncodeToString(bytes)
}
