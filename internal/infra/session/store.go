package session

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/kashguard/go-mpc-wallet/internal/infra/storage"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// StateStore 负责在 Redis + PostgreSQL 之间同步会话/轮次状态，并提供 WAL/指标能力
type StateStore struct {
	metadata storage.MetadataStore
	cache    storage.SessionStore

	walMu        sync.Mutex
	wal          map[string][]*WALRecord
	walSequences map[string]int64
}

var (
	metricsOnce       sync.Once
	roundDurationHist *prometheus.HistogramVec
)

// NewStateStore 创建状态存储器
func NewStateStore(metadata storage.MetadataStore, cache storage.SessionStore) *StateStore {
	ensureRoundMetrics()
	return &StateStore{
		metadata:     metadata,
		cache:        cache,
		wal:          make(map[string][]*WALRecord),
		walSequences: make(map[string]int64),
	}
}

// SaveRoundProgress 将轮次进度持久化到数据库与缓存
func (s *StateStore) SaveRoundProgress(ctx context.Context, progress *RoundProgress) error {
	if progress == nil {
		return errors.New("round progress is nil")
	}
	if progress.SessionID == "" {
		return errors.New("session id is empty")
	}

	stored, err := s.metadata.GetSigningSession(ctx, progress.SessionID)
	if err != nil {
		return errors.Wrap(err, "get signing session")
	}

	if progress.Round > 0 {
		stored.CurrentRound = progress.Round
	}
	if progress.TotalRounds > 0 {
		stored.TotalRounds = progress.TotalRounds
	}
	if len(progress.NodeIDs) > 0 {
		stored.ParticipatingNodes = progress.NodeIDs
	}
	if progress.Status != "" {
		stored.Status = string(progress.Status)
	}
	if progress.Duration > 0 {
		stored.DurationMs = int(progress.Duration.Milliseconds())
	}
	if progress.Message != "" {
		stored.Signature = progress.Message
	}

	if err := s.metadata.UpdateSigningSession(ctx, stored); err != nil {
		return errors.Wrap(err, "update session in metadata store")
	}

	ttl := time.Until(progress.ExpiresAt)
	if ttl <= 0 {
		ttl = time.Minute
	}
	if err := s.cache.UpdateSession(ctx, stored, ttl); err != nil {
		return errors.Wrap(err, "update session cache")
	}

	s.observeRoundMetric(progress.Protocol, progress.Round, progress.Duration)
	return nil
}

// LoadRoundProgress 读取轮次进度（优先 Redis，退回 PostgreSQL）
func (s *StateStore) LoadRoundProgress(ctx context.Context, sessionID string) (*RoundProgress, error) {
	if sessionID == "" {
		return nil, errors.New("session id is empty")
	}

	stored, err := s.cache.GetSession(ctx, sessionID)
	if err != nil {
		stored, err = s.metadata.GetSigningSession(ctx, sessionID)
		if err != nil {
			return nil, errors.Wrap(err, "get session")
		}
	}

	return convertRoundProgress(stored), nil
}

// AppendWAL 追加 WAL 记录
func (s *StateStore) AppendWAL(_ context.Context, record *WALRecord) error {
	if record == nil {
		return errors.New("wal record is nil")
	}
	if record.SessionID == "" {
		return errors.New("wal record missing session id")
	}

	s.walMu.Lock()
	defer s.walMu.Unlock()

	record.Sequence = s.walSequences[record.SessionID] + 1
	s.walSequences[record.SessionID] = record.Sequence
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now()
	}
	s.wal[record.SessionID] = append(s.wal[record.SessionID], record)
	return nil
}

// ReplayWAL 读取并清理 WAL
func (s *StateStore) ReplayWAL(_ context.Context, sessionID string) ([]*WALRecord, error) {
	if sessionID == "" {
		return nil, errors.New("session id is empty")
	}

	s.walMu.Lock()
	defer s.walMu.Unlock()

	records := append([]*WALRecord(nil), s.wal[sessionID]...)
	delete(s.wal, sessionID)
	delete(s.walSequences, sessionID)
	return records, nil
}

// ObserveRoundMetric 暴露轮次耗时指标
func (s *StateStore) ObserveRoundMetric(protocol string, round int, duration time.Duration) {
	s.observeRoundMetric(protocol, round, duration)
}

func (s *StateStore) observeRoundMetric(protocol string, round int, duration time.Duration) {
	if duration <= 0 || round <= 0 {
		return
	}
	ensureRoundMetrics()
	labelRound := fmt.Sprintf("%d", round)
	roundDurationHist.WithLabelValues(protocol, labelRound).Observe(duration.Seconds())
}

func convertRoundProgress(session *storage.SigningSession) *RoundProgress {
	return &RoundProgress{
		SessionID:   session.SessionID,
		KeyID:       session.KeyID,
		Protocol:    session.Protocol,
		Status:      SessionStatus(session.Status),
		Threshold:   session.Threshold,
		TotalNodes:  session.TotalNodes,
		Round:       session.CurrentRound,
		TotalRounds: session.TotalRounds,
		NodeIDs:     append([]string(nil), session.ParticipatingNodes...),
		Message:     session.Signature,
		Duration:    time.Duration(session.DurationMs) * time.Millisecond,
		UpdatedAt:   session.CreatedAt.Add(time.Duration(session.DurationMs) * time.Millisecond),
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}
}

func ensureRoundMetrics() {
	metricsOnce.Do(func() {
		roundDurationHist = promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "mpc",
			Subsystem: "session",
			Name:      "round_duration_seconds",
			Help:      "Round-level latency observed while executing MPC protocols",
			Buckets:   prometheus.ExponentialBuckets(0.0005, 2, 12),
		}, []string{"protocol", "round"})
	})
}
