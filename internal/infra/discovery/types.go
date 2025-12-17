package discovery

import "time"

// ServiceInfo MPC 服务信息（统一类型）
type ServiceInfo struct {
	ID       string            // 服务实例ID
	Name     string            // 服务名称（mpc-participant, mpc-coordinator）
	Address  string            // 服务地址
	Port     int               // 服务端口
	Tags     []string          // 服务标签（node-type:xxx, node-id:xxx, protocol:v1）
	Meta     map[string]string // 元数据
	NodeType string            // 节点类型（coordinator, participant）
}

// HealthCheck 健康检查配置
type HealthCheck struct {
	Type                           string        // "http", "tcp", "grpc"
	Interval                       time.Duration // 检查间隔
	Timeout                        time.Duration // 检查超时
	DeregisterCriticalServiceAfter time.Duration // 关键服务注销时间
	Path                           string        // HTTP健康检查路径
}
