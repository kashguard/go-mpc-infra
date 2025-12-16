package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/kashguard/go-mpc-wallet/internal/config"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/backup"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/key"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/signing"
	pb "github.com/kashguard/go-mpc-wallet/internal/pb/infrastructure/v1"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

// InfrastructureServer 基础设施层 gRPC 服务器
type InfrastructureServer struct {
	pb.UnimplementedKeyServiceServer
	pb.UnimplementedSigningServiceServer
	pb.UnimplementedBackupServiceServer

	keyService    *key.Service
	signingService *signing.Service
	backupService backup.SSSBackupService
	recoveryService *backup.RecoveryService
	cfg           *config.Server
	grpcServer    *grpc.Server
	listener      net.Listener
}

// NewInfrastructureServer 创建基础设施层 gRPC 服务器
func NewInfrastructureServer(
	cfg *config.Server,
	keyService *key.Service,
	signingService *signing.Service,
	backupService backup.SSSBackupService,
	recoveryService *backup.RecoveryService,
) *InfrastructureServer {
	return &InfrastructureServer{
		keyService:      keyService,
		signingService:  signingService,
		backupService:   backupService,
		recoveryService: recoveryService,
		cfg:             cfg,
	}
}

// GetServerOptions 获取 gRPC 服务器选项（mTLS + JWT 认证）
func (s *InfrastructureServer) GetServerOptions() ([]grpc.ServerOption, error) {
	var opts []grpc.ServerOption

	// mTLS 配置
	if s.cfg.MPC.TLSEnabled {
		// 检查 TLS 配置是否完整
		if s.cfg.MPC.TLSCertFile == "" || s.cfg.MPC.TLSKeyFile == "" || s.cfg.MPC.TLSCACertFile == "" {
			return nil, errors.New("TLS is enabled but certificate file paths are not configured. Please set TLSCertFile, TLSKeyFile, and TLSCACertFile")
		}

		// 加载服务器证书
		serverCert, err := tls.LoadX509KeyPair(s.cfg.MPC.TLSCertFile, s.cfg.MPC.TLSKeyFile)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load server certificate")
		}

		// 加载 CA 证书（用于验证客户端证书）
		caCert, err := os.ReadFile(s.cfg.MPC.TLSCACertFile)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read CA certificate")
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to append CA certificate")
		}

		// 配置 mTLS
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert, // 要求客户端证书
			ClientCAs:    caCertPool,
			MinVersion:   tls.VersionTLS13, // 使用 TLS 1.3
		}

		creds := credentials.NewTLS(tlsConfig)
		opts = append(opts, grpc.Creds(creds))

		log.Info().
			Str("cert_file", s.cfg.MPC.TLSCertFile).
			Str("key_file", s.cfg.MPC.TLSKeyFile).
			Str("ca_cert_file", s.cfg.MPC.TLSCACertFile).
			Msg("mTLS enabled for infrastructure gRPC server")
	}

	// KeepAlive 配置
	opts = append(opts, grpc.KeepaliveParams(keepalive.ServerParameters{
		MaxConnectionAge:      2 * time.Hour,
		MaxConnectionAgeGrace: 30 * time.Second,
		Time:                  30 * time.Second,
		Timeout:               20 * time.Second,
	}))

	// 最大消息大小
	opts = append(opts, grpc.MaxRecvMsgSize(10*1024*1024)) // 10MB
	opts = append(opts, grpc.MaxSendMsgSize(10*1024*1024)) // 10MB

	// 认证拦截器（mTLS + JWT）
	opts = append(opts, grpc.UnaryInterceptor(s.authInterceptor))

	return opts, nil
}

// authInterceptor 认证拦截器（mTLS + JWT 双重验证）
func (s *InfrastructureServer) authInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	// 第一步：验证 mTLS 客户端证书
	var appLayerID string
	if s.cfg.MPC.TLSEnabled {
		// 从 gRPC peer 中获取客户端证书
		p, ok := peer.FromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "no peer found in context")
		}

		// 获取 TLS 信息
		tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
		if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
			return nil, status.Error(codes.Unauthenticated, "no client certificate found")
		}

		// 从客户端证书中提取应用层标识
		clientCert := tlsInfo.State.PeerCertificates[0]
		appLayerID = clientCert.Subject.CommonName
		if appLayerID == "" {
			// 尝试从 SAN 中获取
			if len(clientCert.DNSNames) > 0 {
				appLayerID = clientCert.DNSNames[0]
			}
		}

		if appLayerID == "" {
			return nil, status.Error(codes.Unauthenticated, "cannot extract app layer ID from client certificate")
		}

		// 将 appLayerID 注入 context
		ctx = context.WithValue(ctx, "app_layer_id", appLayerID)

		log.Debug().
			Str("app_layer_id", appLayerID).
			Str("method", info.FullMethod).
			Msg("mTLS authentication successful")
	} else {
		// 如果未启用 TLS，使用默认标识（仅用于开发环境）
		appLayerID = "default-app"
		ctx = context.WithValue(ctx, "app_layer_id", appLayerID)
		log.Warn().Msg("TLS disabled, using default app layer ID (development only)")
	}

	// 第二步：验证 JWT Token（可选，用于细粒度授权）
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		authHeaders := md.Get("authorization")
		if len(authHeaders) > 0 {
			token := strings.TrimPrefix(authHeaders[0], "Bearer ")
			// TODO: 实现 JWT 验证逻辑
			// claims, err := validateJWTToken(ctx, token, appLayerID)
			// if err != nil {
			//     return nil, status.Error(codes.Unauthenticated, fmt.Sprintf("invalid JWT token: %v", err))
			// }
			// ctx = context.WithValue(ctx, "app_permissions", claims.Permissions)
			// ctx = context.WithValue(ctx, "app_tenant_id", claims.TenantID)
			_ = token // 暂时忽略，后续实现
		}
	}

	// 将应用层标识注入 context
	ctx = context.WithValue(ctx, "app_layer_id", appLayerID)

	return handler(ctx, req)
}

// Start 启动 gRPC 服务器
func (s *InfrastructureServer) Start(ctx context.Context) error {
	addr := fmt.Sprintf(":%d", s.cfg.MPC.GRPCPort)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return errors.Wrapf(err, "failed to listen on %s", addr)
	}

	s.listener = listener

	// 获取服务器选项
	opts, err := s.GetServerOptions()
	if err != nil {
		return errors.Wrap(err, "failed to get server options")
	}

	// 创建 gRPC 服务器
	s.grpcServer = grpc.NewServer(opts...)

	// 注册服务
	pb.RegisterKeyServiceServer(s.grpcServer, s)
	pb.RegisterSigningServiceServer(s.grpcServer, s)
	pb.RegisterBackupServiceServer(s.grpcServer, s)

	// 启用反射（开发环境）
	reflection.Register(s.grpcServer)

	log.Info().
		Str("address", addr).
		Bool("tls", s.cfg.MPC.TLSEnabled).
		Msg("Starting infrastructure layer gRPC server")

	// 在 goroutine 中启动服务器
	go func() {
		if err := s.grpcServer.Serve(listener); err != nil {
			log.Error().Err(err).Msg("Infrastructure gRPC server failed")
		}
	}()

	// 等待上下文取消
	<-ctx.Done()
	return s.Stop()
}

// Stop 停止 gRPC 服务器
func (s *InfrastructureServer) Stop() error {
	log.Info().Msg("Stopping infrastructure layer gRPC server")

	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}

	if s.listener != nil {
		s.listener.Close()
	}

	return nil
}

