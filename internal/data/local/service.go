package local

import (
	"database/sql"

	"github.com/dropbox/godropbox/time2"
	"github.com/kashguard/go-mpc-wallet/internal/config"
)

type Service struct {
	config config.Server
	db     *sql.DB
	clock  time2.Clock
}

func NewService(config config.Server, db *sql.DB, clock time2.Clock) *Service {
	return &Service{
		config: config,
		db:     db,
		clock:  clock,
	}
}
