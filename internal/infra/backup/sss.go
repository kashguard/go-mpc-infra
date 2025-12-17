package backup

import (
	"crypto/rand"

	"github.com/pkg/errors"
)

// 轻量级 GF(256) Shamir 实现（无外部依赖）

func gfAdd(a, b byte) byte { return a ^ b }
func gfSub(a, b byte) byte { return a ^ b }

// gfMul 使用 0x11b 多项式的逐位乘法（AES 同款）
func gfMul(a, b byte) byte {
	var res byte
	for b > 0 {
		if b&1 == 1 {
			res ^= a
		}
		carry := a & 0x80
		a <<= 1
		if carry != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return res
}

func gfPow(a, n byte) byte {
	var res byte = 1
	for n > 0 {
		if n&1 == 1 {
			res = gfMul(res, a)
		}
		a = gfMul(a, a)
		n >>= 1
	}
	return res
}

func gfInv(a byte) byte {
	if a == 0 {
		return 0
	}
	// a^(254) in GF(256) gives multiplicative inverse
	return gfPow(a, 254)
}

func gfDiv(a, b byte) byte {
	if b == 0 {
		return 0
	}
	return gfMul(a, gfInv(b))
}

// SSS Shamir Secret Sharing 实现（本地 GF(256) 实现，避免外部依赖）
type SSS struct{}

// NewSSS 创建 SSS 实例
func NewSSS() *SSS { return &SSS{} }

// Split 将秘密分割成多个分片（Shamir Secret Sharing）
// threshold: 需要多少个分片才能恢复秘密
// totalShares: 总共生成多少个分片
// 注意：输入是单个MPC分片，不是完整密钥
func (s *SSS) Split(secret []byte, totalShares, threshold int) ([][]byte, error) {
	if threshold < 2 {
		return nil, errors.New("threshold must be at least 2")
	}
	if totalShares < threshold {
		return nil, errors.New("total shares must be at least threshold")
	}
	if totalShares > 255 {
		return nil, errors.New("total shares must be <= 255")
	}
	if len(secret) == 0 {
		return nil, errors.New("secret cannot be empty")
	}

	// 为每个字节生成一个随机多项式（degree = threshold-1，常数项为秘密字节）
	polys := make([][]byte, len(secret))
	for i, b := range secret {
		polys[i] = make([]byte, threshold)
		polys[i][0] = b
		if _, err := rand.Read(polys[i][1:]); err != nil {
			return nil, errors.Wrap(err, "failed to generate random coefficients")
		}
	}

	shares := make([][]byte, totalShares)
	for i := 0; i < totalShares; i++ {
		x := byte(i + 1) // x 从 1 开始
		share := make([]byte, len(secret)+1)
		share[0] = x
		for j := 0; j < len(secret); j++ {
			share[j+1] = evalPoly(polys[j], x)
		}
		shares[i] = share
	}

	return shares, nil
}

// Combine 从分片恢复秘密（Shamir Secret Sharing）
// 需要至少 threshold 个分片
func (s *SSS) Combine(shares [][]byte) ([]byte, error) {
	if len(shares) < 3 {
		return nil, errors.New("need at least 3 shares to recover secret")
	}

	shareLen := len(shares[0])
	for i := 1; i < len(shares); i++ {
		if len(shares[i]) != shareLen {
			return nil, errors.New("all shares must have the same length")
		}
	}

	secretLen := shareLen - 1
	if secretLen <= 0 {
		return nil, errors.New("invalid share format")
	}

	threshold := len(shares)
	secret := make([]byte, secretLen)

	for idx := 0; idx < secretLen; idx++ {
		var acc byte
		for j := 0; j < threshold; j++ {
			xj := shares[j][0]
			yj := shares[j][idx+1]

			// 计算 L_j(0) = Π_{m!=j} (x_m) / (x_m - x_j)
			num := byte(1)
			den := byte(1)
			for m := 0; m < threshold; m++ {
				if m == j {
					continue
				}
				xm := shares[m][0]
				num = gfMul(num, xm)
				den = gfMul(den, gfSub(xm, xj))
			}

			lag := gfDiv(num, den)
			acc = gfAdd(acc, gfMul(yj, lag))
		}
		secret[idx] = acc
	}

	return secret, nil
}

// Horner 多项式求值 f(x) = a0 + a1*x + ... + ak-1*x^(k-1)
func evalPoly(coeffs []byte, x byte) byte {
	if len(coeffs) == 0 {
		return 0
	}
	result := coeffs[len(coeffs)-1]
	for i := len(coeffs) - 2; i >= 0; i-- {
		result = gfMul(result, x)
		result = gfAdd(result, coeffs[i])
	}
	return result
}

