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

func PostBatchSignRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1MPC.POST("/sign/batch", postBatchSignHandler(s))
}

func postBatchSignHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		var body types.PostBatchSignPayload
		if err := util.BindAndValidateBody(c, &body); err != nil {
			return err
		}

		// 构建批量签名请求
		messages := make([]*signing.SignRequest, 0, len(body.Messages))
		for _, msg := range body.Messages {
			var messageBytes []byte
			if msg.Message != nil {
				messageBytes = []byte(*msg.Message)
			} else {
				continue // 跳过无效消息
			}

			messages = append(messages, &signing.SignRequest{
				KeyID:       swag.StringValue(body.KeyID),
				Message:     messageBytes,
				MessageHex:  hex.EncodeToString(messageBytes),
				MessageType: msg.MessageType,
				ChainType:   body.ChainType,
			})
		}

		if len(messages) == 0 {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "no valid messages to sign")
		}

		req := &signing.BatchSignRequest{
			KeyID:     swag.StringValue(body.KeyID),
			Messages:  messages,
			ChainType: body.ChainType,
		}

		resp, err := s.SigningService.BatchSign(ctx, req)
		if err != nil {
			log.Error().Err(err).Msg("Failed to batch sign")
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to batch sign")
		}

		// 构建响应
		responseSignatures := make([]*types.SignResponse, len(resp.Signatures))
		for i, sig := range resp.Signatures {
			responseSignatures[i] = &types.SignResponse{
				Signature:          swag.String(sig.Signature),
				KeyID:              swag.String(sig.KeyID),
				PublicKey:          swag.String(sig.PublicKey),
				Message:            swag.String(sig.Message),
				ChainType:          swag.String(sig.ChainType),
				SessionID:          swag.String(sig.SessionID),
				ParticipatingNodes: sig.ParticipatingNodes,
			}
			if sig.SignedAt != "" {
				if ts, err := time.Parse(time.RFC3339, sig.SignedAt); err == nil {
					responseSignatures[i].SignedAt = strfmt.DateTime(ts)
				}
			}
		}

		total := int64(resp.Total)
		success := int64(resp.Success)
		failed := int64(resp.Failed)

		response := &types.BatchSignResponse{
			Signatures: responseSignatures,
			Total:      &total,
			Success:    &success,
			Failed:     &failed,
		}

		return util.ValidateAndReturn(c, http.StatusOK, response)
	}
}
