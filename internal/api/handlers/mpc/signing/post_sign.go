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

func PostSignRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1MPC.POST("/sign", postSignHandler(s))
}

func postSignHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		var body types.PostSignPayload
		if err := util.BindAndValidateBody(c, &body); err != nil {
			return err
		}

		var message []byte
		if body.Message != nil {
			message = []byte(*body.Message)
		} else {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "message is required")
		}

		req := &signing.SignRequest{
			KeyID:       swag.StringValue(body.KeyID),
			Message:     message,
			MessageHex:  hex.EncodeToString(message),
			MessageType: body.MessageType,
			ChainType:   body.ChainType,
		}

		resp, err := s.SigningService.ThresholdSign(ctx, req)
		if err != nil {
			log.Error().Err(err).Msg("Failed to sign")
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to sign")
		}

		response := &types.SignResponse{
			Signature:          swag.String(resp.Signature),
			KeyID:              swag.String(resp.KeyID),
			PublicKey:          swag.String(resp.PublicKey),
			Message:            swag.String(resp.Message),
			ChainType:          swag.String(resp.ChainType),
			SessionID:          swag.String(resp.SessionID),
			ParticipatingNodes: resp.ParticipatingNodes,
		}
		if resp.SignedAt != "" {
			if ts, err := time.Parse(time.RFC3339, resp.SignedAt); err == nil {
				response.SignedAt = strfmt.DateTime(ts)
			}
		}

		return util.ValidateAndReturn(c, http.StatusOK, response)
	}
}
