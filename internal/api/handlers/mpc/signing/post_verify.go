package signing

import (
	"encoding/hex"
	"net/http"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/kashguard/go-mpc-wallet/internal/api"
	"github.com/kashguard/go-mpc-wallet/internal/api/httperrors"
	"github.com/kashguard/go-mpc-wallet/internal/infra/signing"
	"github.com/kashguard/go-mpc-wallet/internal/types"
	"github.com/kashguard/go-mpc-wallet/internal/util"
	"github.com/labstack/echo/v4"
)

func PostVerifyRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1MPC.POST("/verify", postVerifyHandler(s))
}

func postVerifyHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		var body types.PostVerifyPayload
		if err := util.BindAndValidateBody(c, &body); err != nil {
			return err
		}

		// 准备消息
		var message []byte
		if body.Message != nil {
			message = []byte(*body.Message)
		} else {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "message is required")
		}

		req := &signing.VerifyRequest{
			Signature:  swag.StringValue(body.Signature),
			Message:    message,
			MessageHex: hex.EncodeToString(message),
			PublicKey:  swag.StringValue(body.PublicKey),
			Algorithm:  body.Algorithm,
			ChainType:  body.ChainType,
		}

		resp, err := s.SigningService.Verify(ctx, req)
		if err != nil {
			log.Error().Err(err).Msg("Failed to verify signature")
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to verify signature")
		}

		// 解析verified_at时间
		var verifiedAt *strfmt.DateTime
		if resp.VerifiedAt != "" {
			if ts, err := time.Parse(time.RFC3339, resp.VerifiedAt); err == nil {
				dt := strfmt.DateTime(ts)
				verifiedAt = &dt
			}
		}
		if verifiedAt == nil {
			// 如果解析失败，使用当前时间
			dt := strfmt.DateTime(time.Now())
			verifiedAt = &dt
		}

		response := &types.VerifyResponse{
			Valid:      &resp.Valid,
			PublicKey:  swag.String(resp.PublicKey),
			Address:    resp.Address,
			VerifiedAt: verifiedAt,
		}

		return util.ValidateAndReturn(c, http.StatusOK, response)
	}
}
