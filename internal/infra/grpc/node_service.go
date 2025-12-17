package grpc

import (
	"context"

	"github.com/kashguard/go-mpc-wallet/internal/mpc/node"
	pb "github.com/kashguard/go-mpc-wallet/internal/pb/infra/v1"
	"github.com/kashguard/go-mpc-wallet/internal/util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// RegisterNode 注册新节点
func (s *InfrastructureServer) RegisterNode(ctx context.Context, req *pb.RegisterNodeRequest) (*pb.RegisterNodeResponse, error) {
	log := util.LogFromContext(ctx)

	if req.DeviceId == "" || req.PublicKey == "" {
		return nil, status.Error(codes.InvalidArgument, "device_id and public_key are required")
	}

	var nodeID string

	if req.Type == "client" {
		// 对于 Client，使用 device_id 作为 user_id (或从 metadata 获取)
		// 理想情况下，userID 应该从鉴权信息中提取
		userID := req.DeviceId
		
		// 提取 metadata
		meta := convertMetadata(req.Metadata)
		if req.Version != "" {
			meta["version"] = req.Version
		}

		n, err := s.nodeManager.RegisterClientNode(ctx, userID, req.PublicKey, meta)
		if err != nil {
			log.Error().Err(err).Msg("Failed to register client node")
			return nil, status.Error(codes.Internal, "failed to register node")
		}
		nodeID = n.NodeID
		
		log.Info().
			Str("device_id", req.DeviceId).
			Str("node_id", nodeID).
			Msg("Client node registered successfully")
	} else {
		// Server 节点目前不支持通过 API 动态注册，通常是配置文件定义
		return nil, status.Error(codes.Unimplemented, "server node registration not supported via API")
	}

	return &pb.RegisterNodeResponse{
		NodeId:       nodeID,
		Status:       "active",
		RegisteredAt: timestamppb.Now(),
	}, nil
}

// Heartbeat 节点心跳
func (s *InfrastructureServer) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	if req.NodeId == "" {
		return nil, status.Error(codes.InvalidArgument, "node_id is required")
	}

	if err := s.nodeManager.UpdateHeartbeat(ctx, req.NodeId); err != nil {
		return nil, status.Error(codes.Internal, "failed to update heartbeat")
	}

	return &pb.HeartbeatResponse{
		Success: true,
	}, nil
}

// ListNodes 获取节点列表
func (s *InfrastructureServer) ListNodes(ctx context.Context, req *pb.ListNodesRequest) (*pb.ListNodesResponse, error) {
	// 简单的过滤逻辑
	// 注意：NodeFilter 目前在 storage 包中定义，node.Manager 暴露了 ListNodes
	// 我们需要将 req 转换为 storage.NodeFilter (如果暴露了) 或者 node.Manager 提供参数
	// node.Manager.ListNodes 接受 storage.NodeFilter
	// 但 storage 包在 internal/infra/storage，可能不能直接引用？
	// node 包引用了 storage。
	
	// 由于引用循环限制，我们可能需要 node.Manager 暴露自己的 Filter 类型
	// 但目前 ListNodes 签名是 ListNodes(ctx, *storage.NodeFilter)
	
	// 这里我们暂时返回未实现，或者需要引入 storage 包
	// s.nodeManager.ListNodes 需要 storage.NodeFilter
	
	return nil, status.Error(codes.Unimplemented, "list nodes not implemented yet")
}

// GetNodeConnectionInfo 获取节点连接信息
func (s *InfrastructureServer) GetNodeConnectionInfo(ctx context.Context, req *pb.GetNodeConnectionInfoRequest) (*pb.GetNodeConnectionInfoResponse, error) {
	if req.NodeId == "" {
		return nil, status.Error(codes.InvalidArgument, "node_id is required")
	}

	n, err := s.nodeManager.GetNode(ctx, req.NodeId)
	if err != nil {
		return nil, status.Error(codes.NotFound, "node not found")
	}

	// 构造连接信息
	// 如果是 Server 节点，返回其 gRPC 地址
	// 如果是 Client 节点，通常不可直连，除非有 P2P 穿透
	
	protocol := "grpc"
	address := n.Endpoint
	
	return &pb.GetNodeConnectionInfoResponse{
		Address:   address,
		Protocol:  protocol,
		PublicKey: n.PublicKey,
	}, nil
}

func convertMetadata(m map[string]string) map[string]interface{} {
	res := make(map[string]interface{})
	for k, v := range m {
		res[k] = v
	}
	return res
}
