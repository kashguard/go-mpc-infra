package storage

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
)

// RedisStore Redis存储实现
type RedisStore struct {
	client *redis.Client
}

// NewRedisStore 创建Redis存储实例
func NewRedisStore(client *redis.Client) SessionStore {
	return &RedisStore{client: client}
}

// SaveSession 保存会话状态
func (s *RedisStore) SaveSession(ctx context.Context, session *SigningSession, ttl time.Duration) error {
	data, err := json.Marshal(session)
	if err != nil {
		return errors.Wrap(err, "failed to marshal session")
	}

	key := "mpc:session:" + session.SessionID
	if err := s.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return errors.Wrap(err, "failed to save session")
	}

	return nil
}

// GetSession 获取会话状态
func (s *RedisStore) GetSession(ctx context.Context, sessionID string) (*SigningSession, error) {
	key := "mpc:session:" + sessionID
	data, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, errors.New("session not found")
		}
		return nil, errors.Wrap(err, "failed to get session")
	}

	var session SigningSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal session")
	}

	return &session, nil
}

// UpdateSession 更新会话状态
func (s *RedisStore) UpdateSession(ctx context.Context, session *SigningSession, ttl time.Duration) error {
	return s.SaveSession(ctx, session, ttl)
}

// DeleteSession 删除会话
func (s *RedisStore) DeleteSession(ctx context.Context, sessionID string) error {
	key := "mpc:session:" + sessionID
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return errors.Wrap(err, "failed to delete session")
	}
	return nil
}

// AcquireLock 获取分布式锁
func (s *RedisStore) AcquireLock(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	lockKey := "mpc:lock:" + key
	result, err := s.client.SetNX(ctx, lockKey, "1", ttl).Result()
	if err != nil {
		return false, errors.Wrap(err, "failed to acquire lock")
	}
	return result, nil
}

// ReleaseLock 释放分布式锁
func (s *RedisStore) ReleaseLock(ctx context.Context, key string) error {
	lockKey := "mpc:lock:" + key
	if err := s.client.Del(ctx, lockKey).Err(); err != nil {
		return errors.Wrap(err, "failed to release lock")
	}
	return nil
}

// PublishMessage 发布消息
func (s *RedisStore) PublishMessage(ctx context.Context, channel string, message interface{}) error {
	data, err := json.Marshal(message)
	if err != nil {
		return errors.Wrap(err, "failed to marshal message")
	}

	channelKey := "mpc:channel:" + channel
	if err := s.client.Publish(ctx, channelKey, data).Err(); err != nil {
		return errors.Wrap(err, "failed to publish message")
	}

	return nil
}

// SubscribeMessages 订阅消息
func (s *RedisStore) SubscribeMessages(ctx context.Context, channel string) (<-chan interface{}, error) {
	channelKey := "mpc:channel:" + channel
	pubsub := s.client.Subscribe(ctx, channelKey)

	// 等待确认订阅
	_, err := pubsub.Receive(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to subscribe")
	}

	ch := pubsub.Channel()
	resultCh := make(chan interface{})

	go func() {
		defer close(resultCh)
		defer pubsub.Close()

		for msg := range ch {
			var data interface{}
			if err := json.Unmarshal([]byte(msg.Payload), &data); err != nil {
				continue
			}
			select {
			case resultCh <- data:
			case <-ctx.Done():
				return
			}
		}
	}()

	return resultCh, nil
}
