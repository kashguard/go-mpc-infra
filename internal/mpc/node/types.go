package node

import "time"

// Node 节点信息
type Node struct {
	NodeID        string
	NodeType      string // coordinator, participant
	Endpoint      string
	PublicKey     string
	Status        string // active, inactive, faulty
	Capabilities  []string
	Metadata      map[string]interface{}
	RegisteredAt  time.Time
	LastHeartbeat *time.Time
}

// NodeStatus 节点状态
type NodeStatus string

const (
	NodeStatusActive   NodeStatus = "active"
	NodeStatusInactive NodeStatus = "inactive"
	NodeStatusFaulty   NodeStatus = "faulty"
)

// NodeType 节点类型
type NodeType string

const (
	NodeTypeCoordinator NodeType = "coordinator"
	NodeTypeParticipant NodeType = "participant"
)

// HealthCheck 健康检查结果
type HealthCheck struct {
	NodeID    string
	Status    string
	Timestamp time.Time
	Checks    map[string]string
	Metrics   map[string]float64
}
