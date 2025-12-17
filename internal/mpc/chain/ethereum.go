package chain

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/pkg/errors"
)

// EthereumAdapter 实现 EVM 链基础能力
type EthereumAdapter struct {
	chainID *big.Int
}

// NewEthereumAdapter 创建以太坊适配器
func NewEthereumAdapter(chainID *big.Int) *EthereumAdapter {
	if chainID == nil {
		chainID = big.NewInt(1) // mainnet
	}
	return &EthereumAdapter{chainID: chainID}
}

// GenerateAddress 通过 Keccak256(pubKey[1:]) 生成地址
func (a *EthereumAdapter) GenerateAddress(pubKey []byte) (string, error) {
	if len(pubKey) == 0 {
		return "", errors.New("public key is required")
	}
	var uncompressed64 []byte
	switch {
	case len(pubKey) == 65 && pubKey[0] == 0x04:
		uncompressed64 = pubKey[1:]
	case len(pubKey) == 33 && (pubKey[0] == 0x02 || pubKey[0] == 0x03):
		key, err := btcec.ParsePubKey(pubKey)
		if err != nil {
			return "", errors.Wrap(err, "failed to parse compressed secp256k1 pubkey")
		}
		u := key.SerializeUncompressed() // 65 bytes, 0x04 | X | Y
		uncompressed64 = u[1:]
	default:
		return "", errors.Errorf("unsupported public key format: len=%d", len(pubKey))
	}
	hash := crypto.Keccak256(uncompressed64)
	return fmt.Sprintf("0x%s", hex.EncodeToString(hash[12:])), nil
}

// BuildTransaction 构建一个简化的 RLP 交易负载
func (a *EthereumAdapter) BuildTransaction(req *BuildTxRequest) (*Transaction, error) {
	if req == nil {
		return nil, errors.New("build request is nil")
	}
	if req.Amount == nil {
		return nil, errors.New("amount is required")
	}

	txPayload := []interface{}{
		req.Nonce,
		req.FeeRate, // 这里复用 FeeRate 作为 gas price
		uint64(21000),
		req.To,
		req.Amount,
		req.Data,
		a.chainID,
		uint(0),
		uint(0),
	}

	raw, err := rlp.EncodeToBytes(txPayload)
	if err != nil {
		return nil, errors.Wrap(err, "failed to RLP encode tx payload")
	}

	hash := crypto.Keccak256Hash(raw).Hex()
	return &Transaction{
		Raw:  fmt.Sprintf("0x%s", hex.EncodeToString(raw)),
		Hash: hash,
	}, nil
}
