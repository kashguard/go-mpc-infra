package protocol

import (
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/pkg/errors"
)

// generateKeyID generates a unique key ID
func generateKeyID() string {
	return fmt.Sprintf("key-%d", time.Now().UnixNano())
}

// normalizeNodeIDs ensures node IDs are sorted and have the correct count
func normalizeNodeIDs(ids []string, count int) ([]string, error) {
	if len(ids) == 0 {
		return nil, errors.New("node IDs cannot be empty")
	}
	// Sort IDs for deterministic order
	sortedIDs := make([]string, len(ids))
	copy(sortedIDs, ids)
	sort.Strings(sortedIDs)
	return sortedIDs, nil
}

// resolveMessagePayload decodes the message from hex if needed
func resolveMessagePayload(req *SignRequest) ([]byte, error) {
	if len(req.Message) > 0 {
		return req.Message, nil
	}
	if req.MessageHex != "" {
		return hex.DecodeString(req.MessageHex)
	}
	return nil, errors.New("no message payload provided")
}
