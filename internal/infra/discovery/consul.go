package discovery

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/consul/api"
	"github.com/rs/zerolog/log"
)

// ConsulClient Consul 客户端（简化版，只保留 MPC 需要的功能）
type ConsulClient struct {
	client *api.Client
	config *ConsulConfig
}

// ConsulConfig Consul 配置
type ConsulConfig struct {
	Address string
	Token   string
}

// NewConsulClient 创建 Consul 客户端
func NewConsulClient(cfg *ConsulConfig) (*ConsulClient, error) {
	config := api.DefaultConfig()
	config.Address = cfg.Address
	if cfg.Token != "" {
		config.Token = cfg.Token
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create consul client: %w", err)
	}

	return &ConsulClient{
		client: client,
		config: cfg,
	}, nil
}

// Register 注册服务到 Consul
func (c *ConsulClient) Register(ctx context.Context, service *ServiceInfo) error {
	registration := &api.AgentServiceRegistration{
		ID:      service.ID,
		Name:    service.Name,
		Address: service.Address,
		Port:    service.Port,
		Tags:    service.Tags,
		Meta:    service.Meta,
		Check: &api.AgentServiceCheck{
			// ✅ 使用 TCP 检查代替 gRPC 检查（更简单可靠）
			// Consul 容器从自身网络访问服务，使用服务地址
			TCP:                            fmt.Sprintf("%s:%d", service.Address, service.Port),
			Interval:                       "10s",
			Timeout:                        "5s",
			DeregisterCriticalServiceAfter: "1m",
		},
	}

	if err := c.client.Agent().ServiceRegister(registration); err != nil {
		return fmt.Errorf("failed to register service: %w", err)
	}

	log.Info().
		Str("service_id", service.ID).
		Str("service_name", service.Name).
		Str("address", service.Address).
		Int("port", service.Port).
		Strs("tags", service.Tags).
		Msg("Service registered successfully")

	return nil
}

// Deregister 从 Consul 注销服务
func (c *ConsulClient) Deregister(ctx context.Context, serviceID string) error {
	if err := c.client.Agent().ServiceDeregister(serviceID); err != nil {
		// 如果服务不存在（404错误），只记录警告而不是错误
		// 这通常发生在服务从未成功注册，或已被 Consul 自动注销的情况下
		errStr := err.Error()
		if strings.Contains(errStr, "404") || strings.Contains(errStr, "Unknown service ID") {
			log.Warn().
				Str("service_id", serviceID).
				Err(err).
				Msg("Service not found in Consul, skipping deregistration")
			return nil
		}
		return fmt.Errorf("failed to deregister service: %w", err)
	}

	log.Info().Str("service_id", serviceID).Msg("Service deregistered successfully")
	return nil
}

// Discover 从 Consul 发现服务
func (c *ConsulClient) Discover(ctx context.Context, serviceName string, tags []string) ([]*ServiceInfo, error) {
	services, _, err := c.client.Health().ServiceMultipleTags(serviceName, tags, true, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to discover services %s: %w", serviceName, err)
	}

	result := make([]*ServiceInfo, 0, len(services))
	for _, service := range services {
		result = append(result, &ServiceInfo{
			ID:       service.Service.ID,
			Name:     service.Service.Service,
			Address:  service.Service.Address,
			Port:     service.Service.Port,
			Tags:     service.Service.Tags,
			Meta:     service.Service.Meta,
			NodeType: extractNodeType(service.Service.Tags),
		})
	}

	log.Debug().
		Str("service_name", serviceName).
		Strs("tags", tags).
		Int("found_services", len(result)).
		Int("raw_services_count", len(services)).
		Msg("Service discovery completed")

	// 记录每个发现的服务
	for i, info := range result {
		log.Debug().
			Int("index", i).
			Str("service_id", info.ID).
			Str("address", info.Address).
			Int("port", info.Port).
			Strs("tags", info.Tags).
			Msg("Discovered service")
	}

	return result, nil
}

// extractNodeType 从标签中提取节点类型
func extractNodeType(tags []string) string {
	for _, tag := range tags {
		if len(tag) > 10 && tag[:10] == "node-type:" {
			return tag[10:]
		}
	}
	return ""
}
