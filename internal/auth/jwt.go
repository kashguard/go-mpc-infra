package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
)

// AppClaims defines the custom claims for the application
type AppClaims struct {
	jwt.RegisteredClaims
	TenantID    string   `json:"tenant_id,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	AppID       string   `json:"app_id,omitempty"`
}

// JWTManager handles JWT generation and validation
type JWTManager struct {
	secretKey     []byte
	issuer        string
	tokenDuration time.Duration
}

// NewJWTManager creates a new JWTManager
func NewJWTManager(secretKey string, issuer string, tokenDuration time.Duration) *JWTManager {
	return &JWTManager{
		secretKey:     []byte(secretKey),
		issuer:        issuer,
		tokenDuration: tokenDuration,
	}
}

// Generate creates a new JWT token
func (m *JWTManager) Generate(appID, tenantID string, permissions []string) (string, error) {
	claims := AppClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.tokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    m.issuer,
			Subject:   appID,
		},
		TenantID:    tenantID,
		Permissions: permissions,
		AppID:       appID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secretKey)
}

// Validate validates the JWT token and returns the claims
func (m *JWTManager) Validate(tokenString string) (*AppClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AppClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.secretKey, nil
	})

	if err != nil {
		return nil, errors.Wrap(err, "invalid token")
	}

	claims, ok := token.Claims.(*AppClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}
