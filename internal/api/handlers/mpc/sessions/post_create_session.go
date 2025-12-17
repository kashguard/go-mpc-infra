package sessions

import (
	"net/http"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/kashguard/go-mpc-wallet/internal/api"
	"github.com/kashguard/go-mpc-wallet/internal/api/httperrors"
	"github.com/kashguard/go-mpc-wallet/internal/infra/coordinator"
	"github.com/kashguard/go-mpc-wallet/internal/types"
	"github.com/kashguard/go-mpc-wallet/internal/util"
	"github.com/labstack/echo/v4"
)

func PostCreateSessionRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1MPC.POST("/sessions", postCreateSessionHandler(s))
}

func postCreateSessionHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		var body types.PostCreateSessionPayload
		if err := util.BindAndValidateBody(c, &body); err != nil {
			return err
		}

		var message []byte
		if body.Message != nil {
			message = []byte(*body.Message)
		} else {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "message is required")
		}

		protocol := body.Protocol
		if protocol == "" {
			protocol = string(types.PostCreateSessionPayloadProtocolGg20)
		}

		timeout := body.Timeout
		if timeout == 0 {
			timeout = 300
		}

		req := &coordinator.CreateSessionRequest{
			KeyID:    swag.StringValue(body.KeyID),
			Message:  message,
			Protocol: protocol,
			Timeout:  int(timeout),
		}

		session, err := s.CoordinatorService.CreateSigningSession(ctx, req)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create session")
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to create session")
		}

		response := &types.CreateSessionResponse{
			SessionID:          swag.String(session.SessionID),
			KeyID:              swag.String(session.KeyID),
			Protocol:           swag.String(session.Protocol),
			Status:             swag.String(session.Status),
			Threshold:          util.IntPtrToInt64Ptr(&session.Threshold),
			TotalNodes:         util.IntPtrToInt64Ptr(&session.TotalNodes),
			ParticipatingNodes: session.ParticipatingNodes,
			CreatedAt:          strfmt.DateTime(session.CreatedAt),
			ExpiresAt:          strfmt.DateTime(session.ExpiresAt),
			Timeout:            timeout,
		}

		return util.ValidateAndReturn(c, http.StatusCreated, response)
	}
}
