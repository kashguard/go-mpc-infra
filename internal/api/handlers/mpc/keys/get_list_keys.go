package keys

import (
	"net/http"
	"strconv"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/kashguard/go-mpc-wallet/internal/api"
	"github.com/kashguard/go-mpc-wallet/internal/infra/key"
	"github.com/kashguard/go-mpc-wallet/internal/types"
	"github.com/kashguard/go-mpc-wallet/internal/util"
	"github.com/labstack/echo/v4"
)

func GetListKeysRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1MPC.GET("/keys", getListKeysHandler(s))
}

func getListKeysHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()

		chainType := c.QueryParam("chain_type")
		status := c.QueryParam("status")
		limit := 50
		offset := 0

		if limitStr := c.QueryParam("limit"); limitStr != "" {
			if l, err := strconv.Atoi(limitStr); err == nil {
				limit = l
			}
		}

		if offsetStr := c.QueryParam("offset"); offsetStr != "" {
			if o, err := strconv.Atoi(offsetStr); err == nil {
				offset = o
			}
		}

		filter := &key.KeyFilter{
			ChainType: chainType,
			Status:    status,
			Limit:     limit,
			Offset:    offset,
		}

		keys, err := s.KeyService.ListKeys(ctx, filter)
		if err != nil {
			return err
		}

		responseKeys := make([]*types.GetKeyResponse, len(keys))
		for i, k := range keys {
			responseKeys[i] = &types.GetKeyResponse{
				KeyID:       swag.String(k.KeyID),
				PublicKey:   swag.String(k.PublicKey),
				Algorithm:   swag.String(k.Algorithm),
				Curve:       swag.String(k.Curve),
				Threshold:   util.IntPtrToInt64Ptr(&k.Threshold),
				TotalNodes:  util.IntPtrToInt64Ptr(&k.TotalNodes),
				ChainType:   swag.String(k.ChainType),
				Address:     k.Address,
				Status:      swag.String(k.Status),
				Description: k.Description,
				Tags:        convertTagsToTypes(k.Tags),
				CreatedAt:   strfmt.DateTime(k.CreatedAt),
				UpdatedAt:   strfmt.DateTime(k.UpdatedAt),
			}
		}

		response := &types.ListKeysResponse{
			Keys:   responseKeys,
			Total:  int64(len(keys)),
			Limit:  int64(limit),
			Offset: int64(offset),
		}

		return util.ValidateAndReturn(c, http.StatusOK, response)
	}
}
