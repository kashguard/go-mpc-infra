package keys

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/google/uuid"
	"github.com/kashguard/go-mpc-wallet/internal/api"
	"github.com/kashguard/go-mpc-wallet/internal/api/httperrors"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/coordinator"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/key"
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

		// 如果 Coordinator 服务可用，使用 DKG 会话管理
		var keyMetadata *key.KeyMetadata

		// 添加调试日志（使用 Error 级别确保能看到）
		if s.CoordinatorService == nil {
			log.Error().
				Str("node_type", s.Config.MPC.NodeType).
				Msg("CoordinatorService is nil! Cannot create DKG session. Falling back to direct key creation.")
		} else {
			log.Error().
				Str("node_type", s.Config.MPC.NodeType).
				Msg("Coordinator service is available, proceeding with DKG session creation")
		}

		if s.CoordinatorService != nil {
			// 生成密钥ID（提前生成，用于DKG会话）
			keyID := "key-" + uuid.New().String()
			log.Error().Str("key_id", keyID).Msg("STEP 1: Generated keyID, about to create placeholder key")

			// 先创建一个占位符密钥记录（状态为 Pending），以满足外键约束
			// 这样 DKG 会话可以引用这个 keyID
			// 注意：我们通过 KeyService 来创建占位符，因为它有 MetadataStore 访问权限
			placeholderReq := &key.CreateKeyRequest{
				KeyID:       keyID,
				Algorithm:   swag.StringValue(body.Algorithm),
				Curve:       swag.StringValue(body.Curve),
				Threshold:   int(swag.Int64Value(body.Threshold)),
				TotalNodes:  int(swag.Int64Value(body.TotalNodes)),
				ChainType:   swag.StringValue(body.ChainType),
				Description: body.Description,
				Tags:        convertTags(body.Tags),
			}
			// 创建一个占位符密钥（不执行 DKG，只创建元数据）
			log.Error().Str("key_id", keyID).Msg("STEP 2: Calling CreatePlaceholderKey")
			placeholderKey, err := s.KeyService.CreatePlaceholderKey(ctx, placeholderReq)
			if err != nil {
				log.Error().Err(err).Str("key_id", keyID).Msg("STEP 2 FAILED: Failed to create placeholder key")
				return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to create placeholder key")
			}
			log.Error().Str("key_id", keyID).Str("status", placeholderKey.Status).Msg("STEP 2 SUCCESS: Placeholder key created successfully, now creating DKG session")

			// 创建 DKG 会话请求
			dkgSessionReq := &coordinator.CreateDKGSessionRequest{
				KeyID:      keyID,
				Algorithm:  swag.StringValue(body.Algorithm),
				Curve:      swag.StringValue(body.Curve),
				Protocol:   "", // 使用默认协议
				Threshold:  int(swag.Int64Value(body.Threshold)),
				TotalNodes: int(swag.Int64Value(body.TotalNodes)),
				NodeIDs:    []string{}, // 自动发现节点
			}

			// 创建 DKG 会话（这会创建会话并通知参与者）
			dkgSession, err := s.CoordinatorService.CreateDKGSession(ctx, dkgSessionReq)
			if err != nil {
				log.Error().Err(err).Msg("Failed to create DKG session")
				// 清理占位符密钥
				_ = s.KeyService.DeleteKey(ctx, keyID)
				return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to create DKG session")
			}

			log.Info().
				Str("key_id", keyID).
				Str("session_id", dkgSession.SessionID).
				Strs("participating_nodes", dkgSession.ParticipatingNodes).
				Msg("DKG session created successfully, participants will execute DKG protocol")

			// ✅ 方案一：Coordinator 完全不参与 DKG 协议
			// Coordinator 只负责：
			// 1. 创建 DKG session（已完成）
			// 2. 通知 participants 启动 DKG（通过 NotifyParticipantsForDKG）
			// 3. 等待 DKG 完成后更新密钥元数据（异步，通过轮询或回调）
			//
			// Participants 负责：
			// 1. 接收通知后启动 DKG 协议
			// 2. 执行 DKG 并存储各自的 key share
			// 3. DKG 完成后更新 session 状态

			// 先使用占位符作为初始值，后续轮询会覆盖
			keyMetadata = placeholderKey

			// 同步等待 DKG 完成（与 DKGService 缩短后的默认保持一致）
			waitTimeout := 2 * time.Minute
			pollInterval := 2 * time.Second
			deadline := time.Now().Add(waitTimeout)

			for {
				// 尝试获取最新密钥元数据
				currentKey, err := s.KeyService.GetKey(ctx, keyID)
				if err == nil {
					// 成功获取到元数据时检查状态
					if strings.EqualFold(currentKey.Status, "Active") {
						keyMetadata = currentKey
						log.Info().
							Str("key_id", keyID).
							Str("status", currentKey.Status).
							Strs("participants", dkgSession.ParticipatingNodes).
							Msg("DKG completed successfully, returning Active key")
						break
					}
					if strings.EqualFold(currentKey.Status, "Failed") {
						log.Error().
							Str("key_id", keyID).
							Str("status", currentKey.Status).
							Msg("DKG failed while waiting for completion")
						return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "DKG failed")
					}
					// 未完成继续轮询
					keyMetadata = currentKey
				}

				if time.Now().After(deadline) {
					status := ""
					if keyMetadata != nil {
						status = keyMetadata.Status
					}
					log.Error().
						Str("key_id", keyID).
						Str("status", status).
						Dur("wait_timeout", waitTimeout).
						Msg("DKG did not complete within timeout")
					return httperrors.NewHTTPError(http.StatusGatewayTimeout, types.PublicHTTPErrorTypeGeneric, "DKG did not complete in time")
				}

				time.Sleep(pollInterval)
			}
		} else {
			// 如果没有 Coordinator 服务，使用原有的方式（直接执行 DKG，不使用会话管理）
			req := &key.CreateKeyRequest{
				Algorithm:   swag.StringValue(body.Algorithm),
				Curve:       swag.StringValue(body.Curve),
				Threshold:   int(swag.Int64Value(body.Threshold)),
				TotalNodes:  int(swag.Int64Value(body.TotalNodes)),
				ChainType:   swag.StringValue(body.ChainType),
				Description: body.Description,
				Tags:        convertTags(body.Tags),
			}

			var err error
			keyMetadata, err = s.KeyService.CreateKey(ctx, req)
			if err != nil {
				log.Error().Err(err).Msg("Failed to create key")
				return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to create key")
			}
		}

		response := &types.CreateKeyResponse{
			KeyID:       swag.String(keyMetadata.KeyID),
			PublicKey:   swag.String(keyMetadata.PublicKey),
			Algorithm:   swag.String(keyMetadata.Algorithm),
			Curve:       swag.String(keyMetadata.Curve),
			Threshold:   util.IntPtrToInt64Ptr(&keyMetadata.Threshold),
			TotalNodes:  util.IntPtrToInt64Ptr(&keyMetadata.TotalNodes),
			ChainType:   swag.String(keyMetadata.ChainType),
			Address:     keyMetadata.Address,
			Status:      swag.String(keyMetadata.Status),
			Description: keyMetadata.Description,
			Tags:        body.Tags,
			CreatedAt:   strfmt.DateTime(keyMetadata.CreatedAt),
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
