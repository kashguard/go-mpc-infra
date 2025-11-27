package auth

import (
	"time"

	"github.com/kashguard/go-mpc-wallet/internal/data/dto"
)

type Result struct {
	Token      string
	User       *dto.User
	ValidUntil time.Time
	Scopes     []string
}
