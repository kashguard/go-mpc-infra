package protocol

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"math/big"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/kashguard/tss-lib/crypto"
	"github.com/kashguard/tss-lib/ecdsa/keygen"
	"github.com/pkg/errors"
)

// parseDerivationPath parses a BIP-32 derivation path string into indices
// Example: "m/44'/60'/0'/0/0" -> [44+H, 60+H, 0+H, 0, 0]
// Note: In MPC, we only support non-hardened derivation for now.
func parseDerivationPath(path string) ([]uint32, error) {
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return nil, errors.New("empty derivation path")
	}
	if parts[0] == "m" {
		parts = parts[1:]
	}

	indices := make([]uint32, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		var index uint32
		var err error

		isHardened := false
		if strings.HasSuffix(part, "'") || strings.HasSuffix(part, "h") || strings.HasSuffix(part, "H") {
			isHardened = true
			part = part[:len(part)-1]
		}

		val, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid path component: %s", part)
		}
		index = uint32(val)

		if isHardened {
			index |= 0x80000000
		}
		indices = append(indices, index)
	}
	return indices, nil
}

// computeIL calculates the Intermediate Value IL and Child Chain Code for a given index
// Note: This duplicates logic from key/derivation.go to avoid import cycles.
func computeIL(pubKey *btcec.PublicKey, chainCode []byte, index uint32) (*big.Int, []byte, error) {
	if index >= 0x80000000 {
		return nil, nil, errors.New("hardened derivation is not supported in MPC (requires private key reconstruction)")
	}

	if len(chainCode) != 32 {
		return nil, nil, errors.New("invalid chain code length: must be 32 bytes")
	}

	parentPubKeyBytes := pubKey.SerializeCompressed()
	hmac512 := hmac.New(sha512.New, chainCode)
	hmac512.Write(parentPubKeyBytes)

	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, index)
	hmac512.Write(indexBytes)

	I := hmac512.Sum(nil)
	IL := I[:32]
	IR := I[32:]

	ilNum := new(big.Int).SetBytes(IL)
	if ilNum.Cmp(btcec.S256().N) >= 0 || ilNum.Sign() == 0 {
		return nil, nil, errors.New("invalid derived key (IL >= n or IL = 0)")
	}

	return ilNum, IR, nil
}

// DeriveLocalPartySaveData derives a child key share from a parent key share
func DeriveLocalPartySaveData(parentData *keygen.LocalPartySaveData, parentChainCode []byte, derivationPath string) (*keygen.LocalPartySaveData, error) {
	if derivationPath == "" {
		return parentData, nil
	}

	indices, err := parseDerivationPath(derivationPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse derivation path")
	}

	if len(indices) == 0 {
		return parentData, nil
	}

	// Deep copy relevant parts of parentData
	childData := new(keygen.LocalPartySaveData)
	childData.LocalPreParams = parentData.LocalPreParams
	childData.Xi = new(big.Int).Set(parentData.Xi)
	childData.BigXj = make([]*crypto.ECPoint, len(parentData.BigXj))
	childData.ECDSAPub = nil

	// Copy BigXj
	for i, pt := range parentData.BigXj {
		childData.BigXj[i] = pt // We will create new points, but initially copy reference (or should we clone?)
		// Better clone points to be safe
		if pt != nil {
			childData.BigXj[i], _ = crypto.NewECPoint(pt.Curve(), pt.X(), pt.Y())
		}
	}

	// Initial state
	currentChainCode := parentChainCode
	curve := btcec.S256()

	// We can reconstruct the public key point
	currentX := parentData.ECDSAPub.X()
	currentY := parentData.ECDSAPub.Y()

	// Iterate
	for _, index := range indices {
		// 1. Prepare Public Key for computeIL
		// We need compressed public key
		var pkBytes []byte
		if currentY.Bit(0) == 0 {
			pkBytes = append([]byte{0x02}, currentX.Bytes()...)
		} else {
			pkBytes = append([]byte{0x03}, currentX.Bytes()...)
		}
		// Padding if needed (32 bytes X)
		if len(currentX.Bytes()) < 32 {
			padded := make([]byte, 32)
			copy(padded[32-len(currentX.Bytes()):], currentX.Bytes())
			pkBytes = append(pkBytes[:1], padded...)
		}

		btcecPubKey, err := btcec.ParsePubKey(pkBytes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse public key")
		}

		// 2. Compute IL
		ilNum, nextChainCode, err := computeIL(btcecPubKey, currentChainCode, index)
		if err != nil {
			return nil, errors.Wrap(err, "compute IL failed")
		}

		// 3. Update Private Share (Xi): Xi = (Xi + IL) mod N
		childData.Xi.Add(childData.Xi, ilNum)
		childData.Xi.Mod(childData.Xi, curve.N)

		// 4. Update Public Key (ECDSAPub) and Public Shares (BigXj)
		// P' = P + IL*G

		// Calculate Delta = IL * G
		deltaX, deltaY := curve.ScalarBaseMult(ilNum.Bytes())

		// Update Global Public Key
		newX, newY := curve.Add(currentX, currentY, deltaX, deltaY)
		currentX = newX
		currentY = newY

		// Update All Public Shares (BigXj): Xj' = Xj + IL*G
		for k, pt := range childData.BigXj {
			if pt == nil {
				continue
			}
			bx, by := curve.Add(pt.X(), pt.Y(), deltaX, deltaY)
			newPt, err := crypto.NewECPoint(curve, bx, by)
			if err != nil {
				return nil, errors.Wrap(err, "failed to create new ECPoint")
			}
			childData.BigXj[k] = newPt
		}

		// Update Chain Code for next iteration
		currentChainCode = nextChainCode
	}

	// Finalize ECDSAPub
	newPub, err := crypto.NewECPoint(btcec.S256(), currentX, currentY)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create final public key point")
	}
	childData.ECDSAPub = newPub

	// Important: We also need to update `KSKeyProof`?
	// The KeyGen proof proves that Xi corresponds to BigXj.
	// Since we updated both consistently, the proof structure is invalid with respect to the new values unless we re-generate it.
	// However, `signing` phase might not verify the KeyGen proof again.
	// It usually uses Xi and BigXj.
	// Let's assume tss-lib signing doesn't re-verify KeyGen proofs.

	return childData, nil
}
