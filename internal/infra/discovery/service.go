package discovery

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
)

// Service MPC 服务发现服务
type Service struct {
	consul *ConsulClient
}

// NewService 创建 MPC 服务发现服务
func NewService(consul *ConsulClient) *Service {
	return &Service{
		consul: consul,
	}
}

// RegisterNode 注册 MPC 节点
func (s *Service) RegisterNode(ctx context.Context, nodeID, nodeType, address string, port int) error {
	service := &ServiceInfo{
		ID:      fmt.Sprintf("mpc-%s-%s", nodeType, nodeID),
		Name:    fmt.Sprintf("mpc-%s", nodeType),
		Address: address,
		Port:    port,
		Tags: []string{
			fmt.Sprintf("node-type:%s", nodeType),
			fmt.Sprintf("node-id:%s", nodeID),
			"protocol:v1",
		},
		Meta:     make(map[string]string),
		NodeType: nodeType,
	}

	return s.consul.Register(ctx, service)
}

// DeregisterNode 注销 MPC 节点
func (s *Service) DeregisterNode(ctx context.Context, nodeID, nodeType string) error {
	serviceID := fmt.Sprintf("mpc-%s-%s", nodeType, nodeID)
	return s.consul.Deregister(ctx, serviceID)
}

// DiscoverParticipants 发现参与者节点
func (s *Service) DiscoverParticipants(ctx context.Context, count int) ([]*ServiceInfo, error) {
	services, err := s.consul.Discover(ctx, "mpc-participant", []string{"node-type:participant"})
	if err != nil {
		return nil, err
	}

	// 调试日志：输出每个服务的 Tags
	for i, svc := range services {
		log.Debug().
			Int("index", i).
			Str("service_id", svc.ID).
			Strs("tags", svc.Tags).
			Msg("DiscoverParticipants: service tags")
	}

	log.Debug().
		Int("found_services", len(services)).
		Int("required_count", count).
		Msg("Discovered participants from Consul")

	// 如果找到的服务不足要求的数量，返回错误但仍返回找到的服务
	if len(services) < count {
		return services, fmt.Errorf("insufficient participants: found %d, required %d", len(services), count)
	}

	// 返回前 count 个服务（或全部，如果不足）
	if len(services) > count {
		return services[:count], nil
	}
	return services, nil
}

// DiscoverCoordinator 发现协调者节点
func (s *Service) DiscoverCoordinator(ctx context.Context) (*ServiceInfo, error) {
	services, err := s.consul.Discover(ctx, "mpc-coordinator", []string{"node-type:coordinator"})
	if err != nil {
		return nil, err
	}

	if len(services) == 0 {
		return nil, fmt.Errorf("no coordinator found")
	}

	return services[0], nil
}

// ExtractNodeID 从服务信息中提取节点 ID
func ExtractNodeID(svc *ServiceInfo) string {
	for _, tag := range svc.Tags {
		if strings.HasPrefix(tag, "node-id:") {
			return strings.TrimPrefix(tag, "node-id:")
		}
	}

	// 如果标签中没有，尝试从服务 ID 中提取
	// 服务 ID 格式：mpc-participant-{nodeID} 或 mpc-coordinator-{nodeID}
	if strings.HasPrefix(svc.ID, "mpc-participant-") {
		return strings.TrimPrefix(svc.ID, "mpc-participant-")
	} else if strings.HasPrefix(svc.ID, "mpc-coordinator-") {
		return strings.TrimPrefix(svc.ID, "mpc-coordinator-")
	}

	return ""
}
