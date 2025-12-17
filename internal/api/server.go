package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"github.com/dropbox/godropbox/time2"
	"github.com/kashguard/go-mpc-wallet/internal/config"
	"github.com/kashguard/go-mpc-wallet/internal/data/dto"
	"github.com/kashguard/go-mpc-wallet/internal/data/local"
	"github.com/kashguard/go-mpc-wallet/internal/i18n"
	"github.com/kashguard/go-mpc-wallet/internal/mailer"
	"github.com/kashguard/go-mpc-wallet/internal/metrics"
	"github.com/kashguard/go-mpc-wallet/internal/push"
	"github.com/kashguard/go-mpc-wallet/internal/util"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"

	// MPC imports
	"github.com/kashguard/go-mpc-wallet/internal/infra/coordinator"
	"github.com/kashguard/go-mpc-wallet/internal/infra/discovery"
	infra_grpc "github.com/kashguard/go-mpc-wallet/internal/infra/grpc"
	"github.com/kashguard/go-mpc-wallet/internal/infra/key"
	"github.com/kashguard/go-mpc-wallet/internal/infra/session"
	"github.com/kashguard/go-mpc-wallet/internal/infra/signing"
	mpcgrpc "github.com/kashguard/go-mpc-wallet/internal/mpc/grpc"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/node"

	// Import postgres driver for database/sql package
	_ "github.com/lib/pq"
)

type Router struct {
	Routes     []*echo.Route
	Root       *echo.Group
	Management *echo.Group
	APIV1Auth  *echo.Group
	APIV1Push  *echo.Group
	APIV1MPC   *echo.Group
	WellKnown  *echo.Group
}

// Server is a central struct keeping all the dependencies.
// It is initialized with wire, which handles making the new instances of the components
// in the right order. To add a new component, 3 steps are required:
// - declaring it in this struct
// - adding a provider function in providers.go
// - adding the provider's function name to the arguments of wire.Build() in wire.go
//
// Components labeled as `wire:"-"` will be skipped and have to be initialized after the InitNewServer* call.
// For more information about wire refer to https://pkg.go.dev/github.com/google/wire
type Server struct {
	// skip wire:
	// -> initialized with router.Init(s) function
	Echo   *echo.Echo `wire:"-"`
	Router *Router    `wire:"-"`

	Config  config.Server
	DB      *sql.DB
	Mailer  *mailer.Mailer
	Push    *push.Service
	I18n    *i18n.Service
	Clock   time2.Clock
	Auth    AuthService
	Local   *local.Service
	Metrics *metrics.Service

	// MPC services
	KeyService         *key.Service
	SigningService     *signing.Service
	CoordinatorService *coordinator.Service
	NodeManager        *node.Manager
	NodeRegistry       *node.Registry
	NodeDiscovery      *node.Discovery
	SessionManager     *session.Manager
	DiscoveryService   *discovery.Service // ✅ 新的统一服务发现

	// gRPC services (unified MPC gRPC)
	MPCGRPCServer   *mpcgrpc.GRPCServer              // MPC gRPC 服务端（统一实现）
	MPCGRPCClient   *mpcgrpc.GRPCClient              // MPC gRPC 客户端（用于节点间通信）
	InfraGRPCServer *infra_grpc.InfrastructureServer // Infrastructure gRPC Server (Application Layer)
}

// newServerWithComponents is used by wire to initialize the server components.
// Components not listed here won't be handled by wire and should be initialized separately.
// Components which shouldn't be handled must be labeled `wire:"-"` in Server struct.
func newServerWithComponents(
	cfg config.Server,
	db *sql.DB,
	mail *mailer.Mailer,
	pusher *push.Service,
	i18n *i18n.Service,
	clock time2.Clock,
	auth AuthService,
	local *local.Service,
	metrics *metrics.Service,
	keyService *key.Service,
	signingService *signing.Service,
	coordinatorService *coordinator.Service,
	nodeManager *node.Manager,
	nodeRegistry *node.Registry,
	nodeDiscovery *node.Discovery,
	sessionManager *session.Manager,
	mpcGRPCServer *mpcgrpc.GRPCServer, // ✅ 统一的 MPC gRPC 服务端
	mpcGRPCClient *mpcgrpc.GRPCClient, // ✅ 统一的 MPC gRPC 客户端
	discoveryService *discovery.Service, // ✅ 新的统一服务发现
	infraGRPCServer *infra_grpc.InfrastructureServer,
) *Server {
	s := &Server{
		Config:  cfg,
		DB:      db,
		Mailer:  mail,
		Push:    pusher,
		I18n:    i18n,
		Clock:   clock,
		Auth:    auth,
		Local:   local,
		Metrics: metrics,

		KeyService:         keyService,
		SigningService:     signingService,
		CoordinatorService: coordinatorService,
		NodeManager:        nodeManager,
		NodeRegistry:       nodeRegistry,
		NodeDiscovery:      nodeDiscovery,
		SessionManager:     sessionManager,

		MPCGRPCServer:    mpcGRPCServer,    // ✅ 统一的 MPC gRPC 服务端
		MPCGRPCClient:    mpcGRPCClient,    // ✅ 统一的 MPC gRPC 客户端
		DiscoveryService: discoveryService, // ✅ 新的统一服务发现
		InfraGRPCServer:  infraGRPCServer,
	}

	// 设置 NodeDiscovery 到 MPCGRPCClient，使其能够从 Consul 获取节点信息
	if s.MPCGRPCClient != nil && s.NodeDiscovery != nil {
		s.MPCGRPCClient.SetNodeDiscovery(s.NodeDiscovery)
	}

	return s
}

type AuthService interface {
	GetAppUserProfile(ctx context.Context, id string) (*dto.AppUserProfile, error)
	InitPasswordReset(ctx context.Context, request dto.InitPasswordResetRequest) (dto.InitPasswordResetResult, error)
	Login(ctx context.Context, request dto.LoginRequest) (dto.LoginResult, error)
	Logout(ctx context.Context, request dto.LogoutRequest) error
	Refresh(ctx context.Context, request dto.RefreshRequest) (dto.LoginResult, error)
	Register(ctx context.Context, request dto.RegisterRequest) (dto.RegisterResult, error)
	CompleteRegister(ctx context.Context, request dto.CompleteRegisterRequest) (dto.LoginResult, error)
	DeleteUserAccount(ctx context.Context, request dto.DeleteUserAccountRequest) error
	ResetPassword(ctx context.Context, request dto.ResetPasswordRequest) (dto.LoginResult, error)
	UpdatePassword(ctx context.Context, request dto.UpdatePasswordRequest) (dto.LoginResult, error)
}

func NewServer(config config.Server) *Server {
	s := &Server{
		Config: config,
	}

	return s
}

func (s *Server) Ready() bool {
	if err := util.IsStructInitialized(s); err != nil {
		log.Debug().Err(err).Msg("Server is not fully initialized")
		return false
	}

	return true
}

func (s *Server) Start() error {
	if !s.Ready() {
		return errors.New("server is not ready")
	}

	ctx := context.Background()

	// 1. 注册节点到服务发现（Consul）
	if s.DiscoveryService != nil && s.Config.MPC.NodeID != "" {
		// ✅ 在 docker-compose 网络中使用可解析的主机名：
		// coordinator 使用服务名 "coordinator"（避免使用 nodeID: coordinator-1 导致无法解析）
		// participants 的 nodeID 与服务名一致（participant-1/2/3），可直接使用
		serviceHost := s.Config.MPC.NodeID
		if s.Config.MPC.NodeType == "coordinator" {
			serviceHost = "coordinator"
		}

		log.Info().
			Str("node_id", s.Config.MPC.NodeID).
			Str("node_type", s.Config.MPC.NodeType).
			Str("service_host", serviceHost).
			Int("grpc_port", s.Config.MPC.GRPCPort).
			Msg("Registering node to Consul")

		err := s.DiscoveryService.RegisterNode(ctx, s.Config.MPC.NodeID, s.Config.MPC.NodeType, serviceHost, s.Config.MPC.GRPCPort)
		if err != nil {
			// 注册失败不应阻止服务启动，记录警告日志
			log.Warn().
				Err(err).
				Str("node_id", s.Config.MPC.NodeID).
				Str("node_type", s.Config.MPC.NodeType).
				Msg("Failed to register node to service discovery, continuing startup")
		} else {
			log.Info().
				Str("node_id", s.Config.MPC.NodeID).
				Str("node_type", s.Config.MPC.NodeType).
				Msg("Node registered to service discovery")
		}
	}

	// 2. 启动 MPC gRPC 服务器（如果已初始化）
	// 注意：gRPC 服务器有自己的 Start 方法，它会在 goroutine 中运行并等待 context
	// 使用 context.Background() 让 gRPC 服务器一直运行直到显式停止
	if s.MPCGRPCServer != nil {
		go func() {
			grpcCtx := context.Background() // gRPC 服务器会一直运行，直到在 Shutdown 中显式停止
			if err := s.MPCGRPCServer.Start(grpcCtx); err != nil {
				log.Error().Err(err).Msg("MPC gRPC server failed")
			}
		}()
		log.Info().
			Int("port", s.Config.MPC.GRPCPort).
			Msg("MPC gRPC server started in background")
	}

	// 3. 启动 Infrastructure gRPC 服务器（仅 Coordinator）
	if s.Config.MPC.NodeType == "coordinator" && s.InfraGRPCServer != nil {
		go func() {
			grpcCtx := context.Background()
			if err := s.InfraGRPCServer.Start(grpcCtx); err != nil {
				log.Error().Err(err).Msg("Infrastructure gRPC server failed")
			}
		}()
		log.Info().
			Str("node_type", s.Config.MPC.NodeType).
			Msg("Infrastructure gRPC server started in background")
	} else if s.InfraGRPCServer != nil {
		log.Info().
			Str("node_type", s.Config.MPC.NodeType).
			Msg("Infrastructure gRPC server skipped (not coordinator)")
	}

	// 4. 启动 HTTP 服务器
	// 如果是 Participant，仅启动 HTTP 服务用于健康检查，或者完全禁用业务 API
	// 目前 Echo Server 包含了所有路由，暂时全部启动，但建议在 Router 中进行限制
	// 这里我们根据指令 "API...都不要启动"，如果是 participant，我们可以选择不启动 Echo，
	// 但这会破坏健康检查。我们假设 "API" 指的是 Infrastructure 相关的 gRPC/REST 接口。
	// 为了安全，Participant 不应该暴露 REST API。
	// 如果必须禁用，我们可以在 router 初始化时判断。
	// 但 router.Init 已经在 cmd/server/server.go 中调用了。
	// 我们可以选择在这里不启动 Echo，如果它是 participant。
	// 但那样就没法做 readiness probe 了。
	// 妥协方案：启动 Echo，但依赖 Auth 中间件或网关层保护。
	// 或者，只在 Coordinator 上启动 Echo。
	// 用户明确说 "参与者只参与与协调者的通信...接口要限制都不要启动"。
	// 这意味着 Participant 应该是一个 "无头" 节点，只通过 mTLS 连接 Coordinator。
	// 但是 K8s 部署通常需要 HTTP Probes。
	// 让我们假设 Participant 仍然启动 Echo，但我们记录日志说明。
	if s.Config.MPC.NodeType == "coordinator" {
		if err := s.Echo.Start(s.Config.Echo.ListenAddress); err != nil {
			return fmt.Errorf("failed to start echo server: %w", err)
		}
	} else {
		log.Info().
			Str("node_type", s.Config.MPC.NodeType).
			Msg("HTTP API server skipped (not coordinator). Starting simplified health server if needed.")
		// 也许启动一个简单的 http server 只作为 health check?
		// 为了简单起见，我们遵循用户指令：不启动。
		// 但我们需要阻塞主线程，否则 Start 会立即返回，导致程序退出（如果没有其他阻塞）。
		// MPCGRPCServer 在后台运行，主线程需要阻塞。
		// Echo.Start 是阻塞的。如果跳过它，我们需要手动阻塞。
		// 但 wait, `cmd/server/server.go` waits for `quit` signal.
		// So `s.Start()` non-blocking?
		// No, `s.Echo.Start()` IS blocking.
		// `cmd/server/server.go` calls `go func() { s.Start() }`.
		// So `s.Start()` is expected to block?
		// Echo.Start blocks.
		// If we don't call Echo.Start, `s.Start()` returns `nil` immediately.
		// Then `cmd/server/server.go` waits on signal.
		// So the process acts as a daemon. This is correct behavior.
	}

	return nil
}

func (s *Server) Shutdown(ctx context.Context) []error {
	log.Warn().Msg("Shutting down server")

	var errs []error

	// 1. 注销节点从服务发现（Consul）
	if s.DiscoveryService != nil {
		log.Debug().Msg("Deregistering node from service discovery")
		if err := s.DiscoveryService.DeregisterNode(ctx, s.Config.MPC.NodeID, s.Config.MPC.NodeType); err != nil {
			log.Error().Err(err).Msg("Failed to deregister node from service discovery")
			errs = append(errs, err)
		} else {
			log.Info().
				Str("node_id", s.Config.MPC.NodeID).
				Str("node_type", s.Config.MPC.NodeType).
				Msg("Node deregistered from service discovery")
		}
	}

	// 2. 停止 MPC gRPC 服务器（如果已初始化）
	if s.MPCGRPCServer != nil {
		log.Debug().Msg("Stopping MPC gRPC server")
		if err := s.MPCGRPCServer.Stop(); err != nil {
			log.Error().Err(err).Msg("Failed to stop MPC gRPC server")
			errs = append(errs, err)
		}
	}

	// 3. 关闭 HTTP 服务器
	if s.Echo != nil {
		log.Debug().Msg("Shutting down echo server")
		if err := s.Echo.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error().Err(err).Msg("Failed to shutdown echo server")
			errs = append(errs, err)
		}
	}

	// 4. 关闭数据库连接
	if s.DB != nil {
		log.Debug().Msg("Closing database connection")
		if err := s.DB.Close(); err != nil && !errors.Is(err, sql.ErrConnDone) {
			log.Error().Err(err).Msg("Failed to close database connection")
			errs = append(errs, err)
		}
	}

	return errs
}
