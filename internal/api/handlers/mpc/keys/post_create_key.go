package keys

import (
	"net/http"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/kashguard/go-mpc-wallet/internal/api"
	"github.com/kashguard/go-mpc-wallet/internal/api/httperrors"
	"github.com/kashguard/go-mpc-wallet/internal/infra/key"
	"github.com/kashguard/go-mpc-wallet/internal/types"
	"github.com/kashguard/go-mpc-wallet/internal/util"
	"github.com/labstack/echo/v4"
)

func PostCreateKeyRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1MPC.POST("/keys", postCreateKeyHandler(s))
}

func postCreateKeyHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		var body types.PostCreateKeyPayload
		if err := util.BindAndValidateBody(c, &body); err != nil {
			return err
		}

		// 检查节点类型：密钥创建应该在 Coordinator 节点上进行
		if s.Config.MPC.NodeType != "coordinator" {
			log.Warn().Str("node_type", s.Config.MPC.NodeType).Msg("Key creation is only allowed on coordinator nodes")
			return httperrors.NewHTTPError(http.StatusForbidden, types.PublicHTTPErrorTypeGeneric, "Key creation is only allowed on coordinator nodes")
		}

		// 获取当前用户ID（假设已通过鉴权中间件注入）
		userID, ok := c.Get("user_id").(string)
		if !ok || userID == "" {
			// 如果没有用户ID，使用默认值（开发环境）或报错
			// 这里为了兼容性，暂时使用 "admin"
			userID = "admin"
			log.Warn().Msg("No user_id in context, using default 'admin'")
		}

		// 构建 CreateRootKeyRequest
		req := &key.CreateRootKeyRequest{
			Algorithm:   swag.StringValue(body.Algorithm),
			Curve:       swag.StringValue(body.Curve),
			Threshold:   int(swag.Int64Value(body.Threshold)),
			TotalNodes:  int(swag.Int64Value(body.TotalNodes)),
			Description: body.Description,
			Tags:        convertTags(body.Tags),
			UserID:      userID,
		}

		// 调用 KeyService.CreateRootKey
		// 这会在内部同步执行 DKG，并处理 SSS 备份分片生成和下发
		rootKey, err := s.KeyService.CreateRootKey(ctx, req)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create root key")
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to create root key: "+err.Error())
		}

		log.Info().Str("key_id", rootKey.KeyID).Msg("Root key created successfully")

		// 转换响应
		response := &types.CreateKeyResponse{
			KeyID:       swag.String(rootKey.KeyID),
			PublicKey:   swag.String(rootKey.PublicKey),
			Algorithm:   swag.String(rootKey.Algorithm),
			Curve:       swag.String(rootKey.Curve),
			Threshold:   util.IntPtrToInt64Ptr(&rootKey.Threshold),
			TotalNodes:  util.IntPtrToInt64Ptr(&rootKey.TotalNodes),
			ChainType:   swag.String(""), // Root key has no specific chain type
			Address:     "",              // Root key has no address
			Status:      swag.String(rootKey.Status),
			Description: rootKey.Description,
			Tags:        rootKey.Tags,
			CreatedAt:   strfmt.DateTime(rootKey.CreatedAt),
		}

		return util.ValidateAndReturn(c, http.StatusCreated, response)
	}
}

func convertTags(tags map[string]string) map[string]string {
	if tags == nil {
		return make(map[string]string)
	}
	return tags
}
