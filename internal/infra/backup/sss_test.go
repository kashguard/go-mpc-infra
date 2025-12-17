package backup

import (
	"testing"
)

func TestSSS_SplitAndCombine(t *testing.T) {
	sss := NewSSS()

	// 测试数据
	secret := []byte("test-secret-data-for-sss-backup")
	threshold := 3
	totalShares := 5

	// 分割秘密
	shares, err := sss.Split(secret, totalShares, threshold)
	if err != nil {
		t.Fatalf("Failed to split secret: %v", err)
	}

	if len(shares) != totalShares {
		t.Fatalf("Expected %d shares, got %d", totalShares, len(shares))
	}

	// 测试恢复：使用足够的分片
	recovered, err := sss.Combine(shares[:threshold])
	if err != nil {
		t.Fatalf("Failed to combine shares: %v", err)
	}

	if string(recovered) != string(secret) {
		t.Errorf("Recovered secret does not match original")
		t.Errorf("Original: %s", string(secret))
		t.Errorf("Recovered: %s", string(recovered))
	}

	// 测试恢复：使用不足的分片（应该失败）
	_, err = sss.Combine(shares[:threshold-1])
	if err == nil {
		t.Error("Expected error when combining insufficient shares, got nil")
	}
}

func TestSSS_RecoverWithDifferentShareCombinations(t *testing.T) {
	sss := NewSSS()

	secret := []byte("another-test-secret")
	threshold := 3
	totalShares := 5

	shares, err := sss.Split(secret, totalShares, threshold)
	if err != nil {
		t.Fatalf("Failed to split secret: %v", err)
	}

	// 测试不同的分片组合（3-of-5，选择任意3个）
	testCases := [][]int{
		{0, 1, 2}, // 前3个
		{0, 1, 3}, // 前2个 + 第4个
		{2, 3, 4}, // 后3个
		{0, 2, 4}, // 间隔选择
	}

	for i, indices := range testCases {
		selectedShares := make([][]byte, len(indices))
		for j, idx := range indices {
			selectedShares[j] = shares[idx]
		}

		recovered, err := sss.Combine(selectedShares)
		if err != nil {
			t.Errorf("Test case %d: Failed to combine shares: %v", i, err)
			continue
		}

		if string(recovered) != string(secret) {
			t.Errorf("Test case %d: Recovered secret does not match", i)
		}
	}
}

