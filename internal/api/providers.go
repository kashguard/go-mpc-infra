package api

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/dropbox/godropbox/time2"
	"github.com/kashguard/go-mpc-infra/internal/auth"
	"github.com/kashguard/go-mpc-infra/internal/config"
	"github.com/kashguard/go-mpc-infra/internal/i18n"
	"github.com/kashguard/go-mpc-infra/internal/infra/backup"
	"github.com/kashguard/go-mpc-infra/internal/infra/coordinator"
	"github.com/kashguard/go-mpc-infra/internal/infra/discovery"
	infra_grpc "github.com/kashguard/go-mpc-infra/internal/infra/grpc"
	"github.com/kashguard/go-mpc-infra/internal/infra/key"
	"github.com/kashguard/go-mpc-infra/internal/infra/session"
	"github.com/kashguard/go-mpc-infra/internal/infra/signing"
	"github.com/kashguard/go-mpc-infra/internal/infra/storage"
	"github.com/kashguard/go-mpc-infra/internal/mailer"
	mpcgrpc "github.com/kashguard/go-mpc-infra/internal/mpc/grpc"
	"github.com/kashguard/go-mpc-infra/internal/mpc/node"
	"github.com/kashguard/go-mpc-infra/internal/mpc/protocol"
	"github.com/kashguard/go-mpc-infra/internal/persistence"
	"github.com/kashguard/go-mpc-infra/internal/push"
	"github.com/kashguard/go-mpc-infra/internal/push/provider"
	"github.com/kashguard/tss-lib/tss"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

// PROVIDERS - define here only providers that for various reasons (e.g. cyclic dependency) can't live in their corresponding packages
// or for wrapping providers that only accept sub-configs to prevent the requirements for defining providers for sub-configs.
// https://github.com/google/wire/blob/main/docs/guide.md#defining-providers

// NewPush creates an instance of the push service and registers the configured push providers.
func NewPush(cfg config.Server, db *sql.DB) (*push.Service, error) {
	pusher := push.New(db)

	if cfg.Push.UseFCMProvider {
		fcmProvider, err := provider.NewFCM(cfg.FCMConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create FCM provider: %w", err)
		}
		pusher.RegisterProvider(fcmProvider)
	}

	if cfg.Push.UseMockProvider {
		log.Warn().Msg("Initializing mock push provider")
		mockProvider := provider.NewMock(push.ProviderTypeFCM)
		pusher.RegisterProvider(mockProvider)
	}

	if pusher.GetProviderCount() < 1 {
		log.Warn().Msg("No providers registered for push service")
	}

	return pusher, nil
}

func NewClock(t ...*testing.T) time2.Clock {
	var clock time2.Clock

	useMock := len(t) > 0 && t[0] != nil

	if useMock {
		clock = time2.NewMockClock(time.Now())
	} else {
		clock = time2.DefaultClock
	}

	return clock
}

func NewAuthService(config config.Server, db *sql.DB, clock time2.Clock) *auth.Service {
	return auth.NewService(config, db, clock)
}

func NewMailer(config config.Server) (*mailer.Mailer, error) {
	return mailer.NewWithConfig(config.Mailer, config.SMTP)
}

func NewDB(config config.Server) (*sql.DB, error) {
	return persistence.NewDB(config.Database)
}

func NewI18N(config config.Server) (*i18n.Service, error) {
	return i18n.New(config.I18n)
}

func NoTest() []*testing.T {
	return nil
}

func NewMetadataStore(db *sql.DB) storage.MetadataStore {
	return storage.NewPostgreSQLStore(db)
}

func NewRedisClient(cfg config.Server) (*redis.Client, error) {
	if cfg.MPC.RedisEndpoint == "" {
		return nil, fmt.Errorf("MPC RedisEndpoint is not configured")
	}

	client := redis.NewClient(&redis.Options{
		Addr: cfg.MPC.RedisEndpoint,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to ping redis: %w", err)
	}

	return client, nil
}

func NewSessionStore(client *redis.Client) storage.SessionStore {
	return storage.NewRedisStore(client)
}

func NewKeyShareStorage(cfg config.Server) (storage.KeyShareStorage, error) {
	if cfg.MPC.KeyShareStoragePath == "" {
		return nil, fmt.Errorf("MPC KeyShareStoragePath is not configured")
	}
	if cfg.MPC.KeyShareEncryptionKey == "" {
		return nil, fmt.Errorf("MPC KeyShareEncryptionKey is not configured")
	}
	return storage.NewFileSystemKeyShareStorage(cfg.MPC.KeyShareStoragePath, cfg.MPC.KeyShareEncryptionKey)
}

func NewMPCGRPCClient(cfg config.Server, nodeManager *node.Manager) (*mpcgrpc.GRPCClient, error) {
	return mpcgrpc.NewGRPCClient(cfg, nodeManager)
}

func NewMPCGRPCServer(
	cfg config.Server,
	protocolEngine protocol.Engine,
	sessionManager *session.Manager,
	keyShareStorage storage.KeyShareStorage,
	grpcClient *mpcgrpc.GRPCClient,
	metadataStore storage.MetadataStore,
	backupService backup.SSSBackupService,
) (*mpcgrpc.GRPCServer, error) {
	nodeID := cfg.MPC.NodeID
	if nodeID == "" {
		nodeID = "default-node"
	}

	// 创建协议注册表，注册所有支持的协议引擎
	// 这样 participant 节点可以根据请求中的 Protocol 字段动态选择协议引擎
	registry := protocol.NewProtocolRegistry()
	curve := "secp256k1"
	thisNodeID := nodeID

	// 创建消息路由器（与 NewProtocolEngine 中的逻辑相同）
	messageRouter := func(sessionID string, targetNodeID string, msg tss.Message, isBroadcast bool) error {
		ctx := context.Background()
		if len(sessionID) > 0 && sessionID[:4] == "key-" {
			// DKG消息
			return grpcClient.SendKeygenMessage(ctx, targetNodeID, msg, sessionID, isBroadcast)
		} else {
			// 签名消息
			return grpcClient.SendSigningMessage(ctx, targetNodeID, msg, sessionID)
		}
	}

	// 注册所有支持的协议引擎
	gg18Engine := protocol.NewGG18Protocol(curve, thisNodeID, messageRouter, keyShareStorage)
	gg20Engine := protocol.NewGG20Protocol(curve, thisNodeID, messageRouter, keyShareStorage)
	frostEngine := protocol.NewFROSTProtocol(curve, thisNodeID, messageRouter, keyShareStorage)

	registry.Register("gg18", gg18Engine)
	registry.Register("gg20", gg20Engine)
	registry.Register("frost", frostEngine)

	return mpcgrpc.NewGRPCServerWithRegistry(cfg, protocolEngine, registry, sessionManager, keyShareStorage, metadataStore, backupService, nodeID), nil
}

func NewProtocolEngine(cfg config.Server, grpcClient *mpcgrpc.GRPCClient, keyShareStorage storage.KeyShareStorage) protocol.Engine {
	curve := "secp256k1"
	thisNodeID := cfg.MPC.NodeID
	if thisNodeID == "" {
		thisNodeID = "default-node"
	}

	// 使用真正的gRPC客户端作为消息路由器
	// 参数：sessionID（用于DKG或签名会话），nodeID（目标节点），msg（tss-lib消息）
	messageRouter := func(sessionID string, nodeID string, msg tss.Message, isBroadcast bool) error {
		ctx := context.Background()
		// 根据会话ID判断消息类型（DKG或签名）
		// 如果sessionID是keyID格式（以"key-"开头），则作为DKG消息处理
		// 否则作为签名消息处理
		if len(sessionID) > 0 && sessionID[:4] == "key-" {
			// DKG消息
			log.Error().
				Str("session_id", sessionID).
				Str("target_node_id", nodeID).
				Str("this_node_id", thisNodeID).
				Msg("Routing DKG message to target node")
			err := grpcClient.SendKeygenMessage(ctx, nodeID, msg, sessionID, isBroadcast)
			if err != nil {
				log.Error().
					Err(err).
					Str("session_id", sessionID).
					Str("target_node_id", nodeID).
					Msg("Failed to send DKG message")
			}
			return err
		} else {
			// 签名消息
			return grpcClient.SendSigningMessage(ctx, nodeID, msg, sessionID)
		}
	}

	// 根据配置选择协议
	defaultProtocol := cfg.MPC.DefaultProtocol
	if defaultProtocol == "" {
		defaultProtocol = "gg20"
	}

	switch defaultProtocol {
	case "gg18":
		return protocol.NewGG18Protocol(curve, thisNodeID, messageRouter, keyShareStorage)
	case "gg20":
		return protocol.NewGG20Protocol(curve, thisNodeID, messageRouter, keyShareStorage)
	case "frost":
		return protocol.NewFROSTProtocol(curve, thisNodeID, messageRouter, keyShareStorage)
	default:
		// 默认使用GG20
		return protocol.NewGG20Protocol(curve, thisNodeID, messageRouter, keyShareStorage)
	}
}

func NewNodeManager(metadataStore storage.MetadataStore, cfg config.Server) *node.Manager {
	heartbeat := time.Duration(cfg.MPC.SessionTimeout)
	if heartbeat <= 0 {
		heartbeat = 30
	}
	return node.NewManager(metadataStore, heartbeat*time.Second)
}

func NewNodeRegistry(manager *node.Manager) *node.Registry {
	return node.NewRegistry(manager)
}

// NewMPCDiscoveryService 创建 MPC 服务发现服务
func NewMPCDiscoveryService(cfg config.Server) (*discovery.Service, error) {
	consulClient, err := discovery.NewConsulClient(&discovery.ConsulConfig{
		Address: cfg.MPC.ConsulAddress,
		Token:   "",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create consul client: %w", err)
	}

	return discovery.NewService(consulClient), nil
}

func NewNodeDiscovery(manager *node.Manager, discoveryService *discovery.Service) *node.Discovery {
	return node.NewDiscovery(manager, discoveryService)
}

func NewSessionManager(metadataStore storage.MetadataStore, sessionStore storage.SessionStore, cfg config.Server) *session.Manager {
	timeout := time.Duration(cfg.MPC.SessionTimeout)
	if timeout <= 0 {
		timeout = 300
	}
	return session.NewManager(metadataStore, sessionStore, timeout*time.Second)
}

func NewDKGServiceProvider(
	metadataStore storage.MetadataStore,
	keyShareStorage storage.KeyShareStorage,
	protocolEngine protocol.Engine,
	nodeManager *node.Manager,
	nodeDiscovery *node.Discovery,
	grpcClient *mpcgrpc.GRPCClient, // 用于 coordinator 触发参与者 StartDKG
	cfg config.Server,
) *key.DKGService {
	// 为 DKG 选择协议注册表：与 gRPC server 共用，实现 GG18/GG20/FROST 切换
	registry := protocol.NewProtocolRegistry()
	curve := "secp256k1"
	thisNodeID := cfg.MPC.NodeID
	if thisNodeID == "" {
		thisNodeID = "default-node"
	}

	messageRouter := func(sessionID string, targetNodeID string, msg tss.Message, isBroadcast bool) error {
		ctx := context.Background()
		if len(sessionID) > 0 && sessionID[:4] == "key-" {
			return grpcClient.SendKeygenMessage(ctx, targetNodeID, msg, sessionID, isBroadcast)
		}
		return grpcClient.SendSigningMessage(ctx, targetNodeID, msg, sessionID)
	}

	gg18Engine := protocol.NewGG18Protocol(curve, thisNodeID, messageRouter, keyShareStorage)
	gg20Engine := protocol.NewGG20Protocol(curve, thisNodeID, messageRouter, keyShareStorage)
	frostEngine := protocol.NewFROSTProtocol(curve, thisNodeID, messageRouter, keyShareStorage)

	registry.Register("gg18", gg18Engine)
	registry.Register("gg20", gg20Engine)
	registry.Register("frost", frostEngine)

	// coordinator 节点注入 grpcClient，participant 节点也会构造 DKGService 但不会在本地调用 ExecuteDKG
	return key.NewDKGService(metadataStore, keyShareStorage, protocolEngine, registry, nodeManager, nodeDiscovery, grpcClient)
}

func NewBackupService(metadataStore storage.MetadataStore) backup.SSSBackupService {
	backupStorage, ok := metadataStore.(storage.BackupShareStorage)
	if !ok {
		log.Error().Msg("MetadataStore does not implement BackupShareStorage")
	}
	return backup.NewService(backupStorage, metadataStore)
}

func NewRecoveryService(metadataStore storage.MetadataStore, keyShareStorage storage.KeyShareStorage, backupService backup.SSSBackupService) *backup.RecoveryService {
	backupStorage, ok := metadataStore.(storage.BackupShareStorage)
	if !ok {
		log.Error().Msg("MetadataStore does not implement BackupShareStorage")
	}
	return backup.NewRecoveryService(backupService, backupStorage, keyShareStorage)
}

func NewBackupStore(metadataStore storage.MetadataStore) backup.Store {
	store, ok := metadataStore.(backup.Store)
	if !ok {
		// This should not happen if PostgreSQLStore is used correctly
		log.Fatal().Msg("MetadataStore does not implement backup.Store")
	}
	return store
}

func NewKeyServiceProvider(
	metadataStore storage.MetadataStore,
	keyShareStorage storage.KeyShareStorage,
	protocolEngine protocol.Engine,
	dkgService *key.DKGService,
	backupService backup.SSSBackupService,
) *key.Service {
	return key.NewService(metadataStore, keyShareStorage, protocolEngine, dkgService, backupService)
}

func NewInfrastructureServer(
	cfg config.Server,
	keyService *key.Service,
	signingService *signing.Service,
	backupService backup.SSSBackupService,
	recoveryService *backup.RecoveryService,
	store backup.Store,
	nodeManager *node.Manager,
) *infra_grpc.InfrastructureServer {
	return infra_grpc.NewInfrastructureServer(&cfg, keyService, signingService, backupService, recoveryService, store, nodeManager)
}

func NewSigningServiceProvider(keyService *key.Service, protocolEngine protocol.Engine, sessionManager *session.Manager, nodeDiscovery *node.Discovery, cfg config.Server, grpcClient *mpcgrpc.GRPCClient) *signing.Service {
	defaultProtocol := cfg.MPC.DefaultProtocol
	if defaultProtocol == "" {
		defaultProtocol = "gg20"
	}
	return signing.NewService(keyService, protocolEngine, sessionManager, nodeDiscovery, defaultProtocol, grpcClient)
}

func NewCoordinatorServiceProvider(
	cfg config.Server,
	keyService *key.Service,
	sessionManager *session.Manager,
	nodeDiscovery *node.Discovery,
	protocolEngine protocol.Engine,
	grpcClient *mpcgrpc.GRPCClient,
) *coordinator.Service {
	// coordinator.Service 需要 GRPCClient 接口，mpcgrpc.GRPCClient 实现了该接口
	// 记录配置的 NodeID（用于调试）
	nodeID := cfg.MPC.NodeID
	log.Error().
		Str("mpc_node_id", nodeID).
		Bool("is_empty", nodeID == "").
		Str("mpc_node_type", cfg.MPC.NodeType).
		Msg("NewCoordinatorServiceProvider: creating coordinator service with NodeID")

	return coordinator.NewService(keyService, sessionManager, nodeDiscovery, protocolEngine, grpcClient, nodeID)
}

// ✅ 删除旧的 internal/grpc 相关 providers（已废弃，已统一到 internal/mpc/grpc）
// 统一使用 internal/mpc/grpc 作为唯一的 gRPC 实现
