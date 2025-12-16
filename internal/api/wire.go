//go:build wireinject

//go:generate wire

package api

import (
	"database/sql"
	"testing"

	"github.com/google/wire"
	"github.com/kashguard/go-mpc-wallet/internal/auth"
	"github.com/kashguard/go-mpc-wallet/internal/config"
	"github.com/kashguard/go-mpc-wallet/internal/data/local"
	"github.com/kashguard/go-mpc-wallet/internal/metrics"
)

// INJECTORS - https://github.com/google/wire/blob/main/docs/guide.md#injectors

// serviceSet groups the default set of providers that are required for initing a server
var serviceSet = wire.NewSet(
	newServerWithComponents,
	NewPush,
	NewMailer,
	NewI18N,
	authServiceSet,
	local.NewService,
	metrics.New,
	NewClock,
	mpcServiceSet,
)

var authServiceSet = wire.NewSet(
	NewAuthService,
	wire.Bind(new(AuthService), new(*auth.Service)),
)

var mpcServiceSet = wire.NewSet(
	NewMetadataStore,
	NewRedisClient,
	NewSessionStore,
	NewKeyShareStorage,
	NewNodeManager,
	NewNodeRegistry,
	NewNodeDiscovery,
	NewSessionManager,
	// gRPC communication (must be before NewProtocolEngine)
	NewMPCGRPCClient,
	NewMPCGRPCServer,
	NewProtocolEngine,
	// DKG service (must be before NewKeyServiceProvider)
	NewDKGServiceProvider,
	NewKeyServiceProvider,
	NewSigningServiceProvider,
	NewCoordinatorServiceProvider,
	// Service discovery
	NewMPCDiscoveryService,
)

// InitNewServer returns a new Server instance.
func InitNewServer(
	_ config.Server,
) (*Server, error) {
	wire.Build(serviceSet, NewDB, NoTest)
	return new(Server), nil
}

// InitNewServerWithDB returns a new Server instance with the given DB instance.
// All the other components are initialized via go wire according to the configuration.
func InitNewServerWithDB(
	_ config.Server,
	_ *sql.DB,
	t ...*testing.T,
) (*Server, error) {
	wire.Build(serviceSet)
	return new(Server), nil
}
