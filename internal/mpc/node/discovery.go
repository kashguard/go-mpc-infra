package node

import (
	"context"
	"fmt"

	"github.com/kashguard/go-mpc-wallet/internal/infra/discovery"
	"github.com/kashguard/go-mpc-wallet/internal/infra/storage"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// Discovery 节点发现
type Discovery struct {
	manager          *Manager
	discoveryService *discovery.Service // MPC 服务发现服务
}

// NewDiscovery 创建节点发现器
func NewDiscovery(manager *Manager, discoveryService *discovery.Service) *Discovery {
	return &Discovery{
		manager:          manager,
		discoveryService: discoveryService,
	}
}

// DiscoverNodes 发现节点
// 优先从数据库查询，如果不足则从 Consul 查询
func (d *Discovery) DiscoverNodes(ctx context.Context, nodeType NodeType, status NodeStatus, limit int) ([]*Node, error) {
	filter := &storage.NodeFilter{
		NodeType: string(nodeType),
		Status:   string(status),
		Limit:    limit,
		Offset:   0,
	}

	// 1. 首先从数据库查询
	nodes, err := d.manager.ListNodes(ctx, filter)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list nodes from database")
	}

	// 2. 如果数据库中有足够的节点，直接返回
	if len(nodes) >= limit {
		log.Debug().
			Int("database_nodes", len(nodes)).
			Int("required_nodes", limit).
			Msg("Found sufficient nodes from database")
		return nodes, nil
	}

	// 3. 如果数据库节点不足，从 Consul 发现（只支持参与者）
	if nodeType == NodeTypeParticipant && d.discoveryService != nil {
		log.Debug().
			Int("database_nodes", len(nodes)).
			Int("required_nodes", limit).
			Msg("Database has insufficient nodes, trying Consul discovery")

		// 从 Consul 发现参与者节点
		services, err := d.discoveryService.DiscoverParticipants(ctx, limit)
		if err != nil {
			// 如果 Consul 发现也失败，返回数据库中的节点（即使不够）
			log.Warn().
				Err(err).
				Int("database_nodes", len(nodes)).
				Int("required_nodes", limit).
				Msg("Failed to discover participants from Consul, returning nodes from database")
			return nodes, nil
		}

		log.Debug().
			Int("consul_services", len(services)).
			Int("required_nodes", limit).
			Msg("Discovered participants from Consul")

		// 4. 转换 discovery.ServiceInfo → node.Node
		consulNodes := make([]*Node, 0, len(services))
		for _, svc := range services {
			// 从服务信息中提取节点 ID
			nodeID := discovery.ExtractNodeID(svc)
			if nodeID == "" {
				log.Warn().
					Str("service_id", svc.ID).
					Strs("tags", svc.Tags).
					Msg("Failed to extract node ID from service, skipping")
				continue
			}

			// 构建 endpoint
			endpoint := fmt.Sprintf("%s:%d", svc.Address, svc.Port)

			// 转换为 Node
			consulNode := &Node{
				NodeID:       nodeID,
				NodeType:     svc.NodeType,
				Endpoint:     endpoint,
				Status:       string(status), // 使用请求的状态
				Capabilities: []string{},     // Consul 中暂无 capabilities
				Metadata:     make(map[string]interface{}),
			}

			// 调试日志：记录转换后的节点信息
			log.Debug().
				Str("node_id", consulNode.NodeID).
				Str("node_type", consulNode.NodeType).
				Str("endpoint", consulNode.Endpoint).
				Str("service_id", svc.ID).
				Strs("service_tags", svc.Tags).
				Msg("Converted Consul service to Node")

			consulNodes = append(consulNodes, consulNode)
		}

		// 5. 合并数据库节点和 Consul 节点
		allNodes := append(nodes, consulNodes...)

		// 6. 去重（基于 nodeID）
		uniqueNodes := make(map[string]*Node)
		for _, n := range allNodes {
			uniqueNodes[n.NodeID] = n
		}

		// 7. 转换为切片
		result := make([]*Node, 0, len(uniqueNodes))
		for _, n := range uniqueNodes {
			result = append(result, n)
		}

		log.Debug().
			Int("total_nodes", len(result)).
			Int("database_nodes", len(nodes)).
			Int("consul_nodes", len(consulNodes)).
			Int("required_nodes", limit).
			Msg("Merged nodes from database and Consul")

		return result, nil
	}

	// 如果不是参与者节点，或者没有配置服务发现，返回数据库中的节点
	return nodes, nil
}
