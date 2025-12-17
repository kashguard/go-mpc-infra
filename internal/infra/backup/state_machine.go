package backup

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kashguard/go-mpc-wallet/internal/infra/storage"
)

var (
	ErrInvalidTransition = errors.New("invalid state transition")
	ErrDeliveryNotFound  = errors.New("delivery not found")
)

type StateMachine struct {
	store Store
}

func NewStateMachine(store Store) *StateMachine {
	return &StateMachine{store: store}
}

// StartDelivery initiates a new delivery process
func (sm *StateMachine) StartDelivery(ctx context.Context, keyID, nodeID, userID string, shareIndex int) (*storage.BackupShareDelivery, error) {
	// Check if already exists
	existing, err := sm.store.GetBackupShareDelivery(ctx, keyID, userID, nodeID, shareIndex)
	if err == nil && existing != nil {
		// If exists and not failed, return it.
		if existing.Status != DeliveryStatusFailed {
			return existing, nil
		}
		// If failed, reset to pending
		err = sm.store.UpdateBackupShareDeliveryStatus(ctx, keyID, userID, nodeID, shareIndex, DeliveryStatusPending, "")
		if err != nil {
			return nil, err
		}
		existing.Status = DeliveryStatusPending
		return existing, nil
	}

	delivery := &storage.BackupShareDelivery{
		KeyID:      keyID,
		NodeID:     nodeID,
		UserID:     userID,
		ShareIndex: shareIndex,
		Status:     DeliveryStatusPending,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := sm.store.SaveBackupShareDelivery(ctx, delivery); err != nil {
		return nil, err
	}

	return delivery, nil
}

func (sm *StateMachine) TransitionToDelivered(ctx context.Context, keyID, userID, nodeID string, shareIndex int) error {
	delivery, err := sm.store.GetBackupShareDelivery(ctx, keyID, userID, nodeID, shareIndex)
	if err != nil {
		return err
	}
	if delivery == nil {
		return ErrDeliveryNotFound
	}

	if !canTransition(delivery.Status, DeliveryStatusDelivered) {
		return fmt.Errorf("%w: from %s to %s", ErrInvalidTransition, delivery.Status, DeliveryStatusDelivered)
	}

	return sm.store.UpdateBackupShareDeliveryStatus(ctx, keyID, userID, nodeID, shareIndex, DeliveryStatusDelivered, "")
}

func (sm *StateMachine) TransitionToConfirmed(ctx context.Context, keyID, userID, nodeID string, shareIndex int) error {
	delivery, err := sm.store.GetBackupShareDelivery(ctx, keyID, userID, nodeID, shareIndex)
	if err != nil {
		return err
	}
	if delivery == nil {
		return ErrDeliveryNotFound
	}

	if !canTransition(delivery.Status, DeliveryStatusConfirmed) {
		return fmt.Errorf("%w: from %s to %s", ErrInvalidTransition, delivery.Status, DeliveryStatusConfirmed)
	}

	return sm.store.UpdateBackupShareDeliveryStatus(ctx, keyID, userID, nodeID, shareIndex, DeliveryStatusConfirmed, "")
}

func (sm *StateMachine) TransitionToFailed(ctx context.Context, keyID, userID, nodeID string, shareIndex int, reason string) error {
	delivery, err := sm.store.GetBackupShareDelivery(ctx, keyID, userID, nodeID, shareIndex)
	if err != nil {
		return err
	}
	if delivery == nil {
		return ErrDeliveryNotFound
	}

	if delivery.Status == DeliveryStatusConfirmed {
		return fmt.Errorf("%w: cannot fail a confirmed delivery", ErrInvalidTransition)
	}

	return sm.store.UpdateBackupShareDeliveryStatus(ctx, keyID, userID, nodeID, shareIndex, DeliveryStatusFailed, reason)
}

func canTransition(current, next string) bool {
	switch current {
	case DeliveryStatusPending:
		return next == DeliveryStatusDelivered || next == DeliveryStatusFailed
	case DeliveryStatusDelivered:
		return next == DeliveryStatusConfirmed || next == DeliveryStatusFailed
	case DeliveryStatusFailed:
		// Can retry -> Pending
		return next == DeliveryStatusPending
	case DeliveryStatusConfirmed:
		return false
	default:
		return false
	}
}
