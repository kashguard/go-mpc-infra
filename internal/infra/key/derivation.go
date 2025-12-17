package key

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/pkg/errors"
)

// DerivationService 负责密钥派生
type DerivationService struct{}

// NewDerivationService 创建密钥派生服务
func NewDerivationService() *DerivationService {
	return &DerivationService{}
}

// DeriveChildKeyRequest 派生请求参数
type DeriveChildKeyRequest struct {
	ParentPubKey    []byte
	ParentChainCode []byte
	Curve           string
	Index           uint32
}

// DerivedKeyResult 派生结果
type DerivedKeyResult struct {
	PublicKey []byte
	ChainCode []byte
}

// GenerateRandomChainCode 生成随机 ChainCode
func (s *DerivationService) GenerateRandomChainCode() ([]byte, error) {
	chainCode := make([]byte, 32)
	if _, err := rand.Read(chainCode); err != nil {
		return nil, errors.Wrap(err, "failed to generate random chain code")
	}
	return chainCode, nil
}

// ParseDerivationPath 解析派生路径 (e.g. "m/44'/60'/0'/0/0")
// 支持 ' 或 h 表示 hardened
func (s *DerivationService) ParseDerivationPath(path string) ([]uint32, error) {
	if path == "" || path == "m" || path == "/" {
		return []uint32{}, nil
	}

	parts := strings.Split(path, "/")
	if parts[0] == "m" {
		parts = parts[1:]
	}

	indices := make([]uint32, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}

		var index uint32
		var hardened bool

		if strings.HasSuffix(part, "'") {
			hardened = true
			part = strings.TrimSuffix(part, "'")
		} else if strings.HasSuffix(part, "h") {
			hardened = true
			part = strings.TrimSuffix(part, "h")
		}

		val, err := strings.NewReader(part).ReadByte() // Dummy check, use ParseUint
		_ = val
		_ = err

		// Parse number
		// We use fmt.Sscanf or similar since Atoi doesn't handle uint32 range well with bitwise ops if we were doing it manually, but strconv is fine
		// Let's use simple logic
		n := new(big.Int)
		_, ok := n.SetString(part, 10)
		if !ok {
			return nil, errors.Errorf("invalid path component: %s", part)
		}

		index = uint32(n.Uint64())
		if hardened {
			index |= 0x80000000
		}
		indices = append(indices, index)
	}
	return indices, nil
}

// DerivePublicKeyFromPath 根据路径派生最终公钥
func (s *DerivationService) DerivePublicKeyFromPath(parentPubKey []byte, parentChainCode []byte, curve string, path string) (*DerivedKeyResult, error) {
	indices, err := s.ParseDerivationPath(path)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse path")
	}

	currentPubKey := parentPubKey
	currentChainCode := parentChainCode

	for i, index := range indices {
		req := &DeriveChildKeyRequest{
			ParentPubKey:    currentPubKey,
			ParentChainCode: currentChainCode,
			Curve:           curve,
			Index:           index,
		}

		res, err := s.DeriveChildKey(req)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to derive at index %d (%d)", i, index)
		}

		currentPubKey = res.PublicKey
		currentChainCode = res.ChainCode
	}

	return &DerivedKeyResult{
		PublicKey: currentPubKey,
		ChainCode: currentChainCode,
	}, nil
}

// DeriveChildKey 执行单步派生
func (s *DerivationService) DeriveChildKey(req *DeriveChildKeyRequest) (*DerivedKeyResult, error) {
	if req.Curve == "" {
		return nil, errors.New("curve is required")
	}

	// Standardize curve name
	curve := strings.ToLower(req.Curve)
	if curve == "secp256k1" {
		return s.deriveSecp256k1(req.ParentPubKey, req.ParentChainCode, req.Index)
	}

	if curve == "ed25519" {
		return s.deriveEd25519(req.ParentPubKey, req.ParentChainCode, req.Index)
	}

	return nil, errors.Errorf("unsupported curve for derivation: %s", req.Curve)
}

// deriveEd25519 使用 BIP-32-Ed25519 (Slip-0010) 的非强化变体进行派生
// 注意：标准 Ed25519 只支持 Hardened Derivation，这里实现的是 MPC 常用的加法同态变体
// P_child = P_parent + IL * G
func (s *DerivationService) deriveEd25519(pubKey []byte, chainCode []byte, index uint32) (*DerivedKeyResult, error) {
	ilNum, IR, err := s.computeIL(pubKey, chainCode, index)
	if err != nil {
		return nil, err
	}

	// 解析父公钥
	// Ed25519 公钥是 32 字节
	if len(pubKey) != 32 {
		return nil, errors.New("invalid ed25519 public key length")
	}

	parentPoint, err := edwards.ParsePubKey(pubKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse ed25519 public key")
	}

	// 计算子公钥点：Ki = P + IL * G
	// IL 需要 mod Order
	curve := edwards.Edwards()
	ilMod := new(big.Int).Mod(ilNum, curve.N)

	// IL * G
	ilx, ily := curve.ScalarBaseMult(ilMod.Bytes())

	// P + (IL * G)
	childX, childY := curve.Add(parentPoint.X, parentPoint.Y, ilx, ily)

	// 序列化子公钥 (32 bytes, y-coordinate with sign bit of x)
	// dcrec/edwards/v2 Use Serialize() which returns 32-byte compressed format
	childPoint := edwards.PublicKey{
		Curve: curve,
		X:     childX,
		Y:     childY,
	}

	childPubKeyBytes := childPoint.Serialize()

	return &DerivedKeyResult{
		PublicKey: childPubKeyBytes,
		ChainCode: IR,
	}, nil
}

// computeIL 计算中间变量 IL
func (s *DerivationService) computeIL(pubKey []byte, chainCode []byte, index uint32) (*big.Int, []byte, error) {
	// 检查是否是 Hardened Derivation (index >= 2^31)
	if index >= 0x80000000 {
		return nil, nil, errors.New("hardened derivation is not supported without private key")
	}

	if len(chainCode) != 32 {
		return nil, nil, errors.New("invalid chain code length: must be 32 bytes")
	}

	var parentPubKeyBytes []byte
	var curveOrder *big.Int

	// 尝试判断公钥类型
	if len(pubKey) == 32 {
		// 假设是 Ed25519
		parentPubKeyBytes = pubKey
		curveOrder = edwards.Edwards().N
	} else {
		// 尝试作为 Secp256k1 解析
		parentPubKey, err := btcec.ParsePubKey(pubKey)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to parse parent public key (must be secp256k1 or 32-byte ed25519)")
		}
		parentPubKeyBytes = parentPubKey.SerializeCompressed()
		curveOrder = btcec.S256().N
	}

	// 计算 HMAC-SHA512
	hmac512 := hmac.New(sha512.New, chainCode)
	hmac512.Write(parentPubKeyBytes)

	// 写入 Index (Big Endian)
	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, index)
	hmac512.Write(indexBytes)

	I := hmac512.Sum(nil)
	IL := I[:32]
	IR := I[32:]

	// IL 解释为整数
	ilNum := new(big.Int).SetBytes(IL)

	// 验证 IL < n
	if ilNum.Cmp(curveOrder) >= 0 || ilNum.Sign() == 0 {
		return nil, nil, errors.New("invalid derived key (IL >= n or IL = 0)")
	}

	return ilNum, IR, nil
}

// deriveSecp256k1 使用 BIP-32 进行 Secp256k1 派生 (Non-Hardened Only)
func (s *DerivationService) deriveSecp256k1(pubKey []byte, chainCode []byte, index uint32) (*DerivedKeyResult, error) {
	ilNum, IR, err := s.computeIL(pubKey, chainCode, index)
	if err != nil {
		return nil, err
	}

	// 解析父公钥对象用于计算
	parentPubKey, _ := btcec.ParsePubKey(pubKey) // 已在 computeIL 中验证过

	// 计算子公钥点：Ki = P + IL * G
	ilx, ily := btcec.S256().ScalarBaseMult(ilNum.Bytes())
	pubKeyECDSA := parentPubKey.ToECDSA()
	childX, childY := btcec.S256().Add(pubKeyECDSA.X, pubKeyECDSA.Y, ilx, ily)

	if childX.Sign() == 0 && childY.Sign() == 0 {
		return nil, errors.New("invalid derived key (point at infinity)")
	}

	// 序列化子公钥
	uncompressed := make([]byte, 65)
	uncompressed[0] = 0x04
	childXBytes := childX.Bytes()
	childYBytes := childY.Bytes()
	copy(uncompressed[33-len(childXBytes):33], childXBytes)
	copy(uncompressed[65-len(childYBytes):65], childYBytes)

	childKeyObj, err := btcec.ParsePubKey(uncompressed)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse derived public key")
	}

	childKeyCompressed := childKeyObj.SerializeCompressed()

	return &DerivedKeyResult{
		PublicKey: childKeyCompressed,
		ChainCode: IR,
	}, nil
}

// DerivePrivateKeyShare 派生私钥分片 (Homomorphic Derivation)
// 适用于 MPC 场景：每个节点使用相同的 parentPubKey 和 chainCode，结合自己的 share 进行计算
// NewShare = (OldShare + IL) mod n
func (s *DerivationService) DerivePrivateKeyShare(share *big.Int, parentPubKey []byte, chainCode []byte, index uint32) (*big.Int, error) {
	if share == nil {
		return nil, errors.New("share cannot be nil")
	}

	// 计算 IL
	ilNum, _, err := s.computeIL(parentPubKey, chainCode, index)
	if err != nil {
		return nil, err
	}

	// 计算新分片：(Share + IL) mod N
	// 注意：在 SSS 中，如果是 f(x) + IL，则每个点的 y 值都要加上 IL
	// 这适用于 GG18/GG20 等协议的加法同态特性
	curveOrder := btcec.S256().N
	newShare := new(big.Int).Add(share, ilNum)
	newShare.Mod(newShare, curveOrder)

	return newShare, nil
}
