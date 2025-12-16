package storage

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/scrypt"
)

// FileSystemKeyShareStorage 文件系统密钥分片存储实现
type FileSystemKeyShareStorage struct {
	basePath      string
	encryptionKey []byte
}

// NewFileSystemKeyShareStorage 创建文件系统密钥分片存储实例
func NewFileSystemKeyShareStorage(basePath string, encryptionKey string) (KeyShareStorage, error) {
	// 从字符串密钥派生加密密钥
	key, err := deriveKey(encryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive encryption key")
	}

	// 确保基础路径存在
	if err := os.MkdirAll(basePath, 0700); err != nil {
		return nil, errors.Wrap(err, "failed to create base path")
	}

	return &FileSystemKeyShareStorage{
		basePath:      basePath,
		encryptionKey: key,
	}, nil
}

// deriveKey 从字符串密钥派生加密密钥
func deriveKey(password string) ([]byte, error) {
	salt := []byte("mpc-key-share-salt") // 固定salt，实际应该从配置读取
	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// getFilePath 获取密钥分片文件路径
func (s *FileSystemKeyShareStorage) getFilePath(keyID, nodeID string) string {
	return filepath.Join(s.basePath, keyID, nodeID+".enc")
}

// encrypt 加密数据
func (s *FileSystemKeyShareStorage) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.Wrap(err, "failed to generate nonce")
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decrypt 解密数据
func (s *FileSystemKeyShareStorage) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt")
	}

	return plaintext, nil
}

// StoreKeyShare 存储密钥分片（加密）
func (s *FileSystemKeyShareStorage) StoreKeyShare(ctx context.Context, keyID string, nodeID string, share []byte) error {
	// 加密分片
	encrypted, err := s.encrypt(share)
	if err != nil {
		return errors.Wrap(err, "failed to encrypt key share")
	}

	// 获取文件路径
	filePath := s.getFilePath(keyID, nodeID)
	dirPath := filepath.Dir(filePath)

	// 创建目录
	if err := os.MkdirAll(dirPath, 0700); err != nil {
		return errors.Wrap(err, "failed to create directory")
	}

	// 写入文件（使用临时文件然后原子重命名）
	tmpPath := filePath + ".tmp"
	if err := os.WriteFile(tmpPath, encrypted, 0600); err != nil {
		return errors.Wrap(err, "failed to write encrypted share")
	}

	if err := os.Rename(tmpPath, filePath); err != nil {
		return errors.Wrap(err, "failed to rename temp file")
	}

	return nil
}

// GetKeyShare 获取密钥分片（解密）
func (s *FileSystemKeyShareStorage) GetKeyShare(ctx context.Context, keyID string, nodeID string) ([]byte, error) {
	filePath := s.getFilePath(keyID, nodeID)

	// 读取加密文件
	encrypted, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("key share not found")
		}
		return nil, errors.Wrap(err, "failed to read encrypted share")
	}

	// 解密分片
	share, err := s.decrypt(encrypted)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt key share")
	}

	return share, nil
}

// DeleteKeyShare 删除密钥分片
func (s *FileSystemKeyShareStorage) DeleteKeyShare(ctx context.Context, keyID string, nodeID string) error {
	filePath := s.getFilePath(keyID, nodeID)

	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			return nil // 文件不存在，认为已删除
		}
		return errors.Wrap(err, "failed to delete key share")
	}

	// 如果目录为空，尝试删除目录
	dirPath := filepath.Dir(filePath)
	if dir, err := os.Open(dirPath); err == nil {
		defer dir.Close()
		if _, err := dir.Readdirnames(1); err == io.EOF {
			// 目录为空，删除
			os.Remove(dirPath)
		}
	}

	return nil
}

// ListKeyShares 列出所有密钥分片
func (s *FileSystemKeyShareStorage) ListKeyShares(ctx context.Context, nodeID string) ([]string, error) {
	var keyIDs []string

	// 遍历所有key目录
	err := filepath.Walk(s.basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 检查是否是目标节点的加密文件
		if !info.IsDir() && filepath.Base(path) == nodeID+".enc" {
			// 提取keyID（目录名）
			keyID := filepath.Base(filepath.Dir(path))
			keyIDs = append(keyIDs, keyID)
		}

		return nil
	})

	if err != nil {
		return nil, errors.Wrap(err, "failed to list key shares")
	}

	return keyIDs, nil
}

// StoreKeyData 存储密钥数据（LocalPartySaveData 序列化后的数据，加密存储）
func (s *FileSystemKeyShareStorage) StoreKeyData(ctx context.Context, keyID string, nodeID string, keyData []byte) error {
	// 加密数据
	encrypted, err := s.encrypt(keyData)
	if err != nil {
		return errors.Wrap(err, "failed to encrypt key data")
	}

	// 获取文件路径（使用 .keydata 扩展名以区分密钥分片）
	filePath := filepath.Join(s.basePath, keyID, nodeID+".keydata.enc")
	dirPath := filepath.Dir(filePath)

	// 创建目录
	if err := os.MkdirAll(dirPath, 0700); err != nil {
		return errors.Wrap(err, "failed to create directory")
	}

	// 写入文件（使用临时文件然后原子重命名）
	tmpPath := filePath + ".tmp"
	if err := os.WriteFile(tmpPath, encrypted, 0600); err != nil {
		return errors.Wrap(err, "failed to write encrypted key data")
	}

	if err := os.Rename(tmpPath, filePath); err != nil {
		return errors.Wrap(err, "failed to rename temp file")
	}

	return nil
}

// GetKeyData 获取密钥数据（解密并返回序列化的 LocalPartySaveData）
func (s *FileSystemKeyShareStorage) GetKeyData(ctx context.Context, keyID string, nodeID string) ([]byte, error) {
	filePath := filepath.Join(s.basePath, keyID, nodeID+".keydata.enc")

	// ✅ 添加详细日志
	log.Info().
		Str("key_id", keyID).
		Str("node_id", nodeID).
		Str("file_path", filePath).
		Str("base_path", s.basePath).
		Msg("🔍 [DIAGNOSTIC] GetKeyData: attempting to load LocalPartySaveData")

	// 读取加密文件
	encrypted, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Error().
				Str("key_id", keyID).
				Str("node_id", nodeID).
				Str("file_path", filePath).
				Msg("🔍 [DIAGNOSTIC] GetKeyData: file does not exist")
			return nil, errors.New("key data not found")
		}
		log.Error().
			Err(err).
			Str("key_id", keyID).
			Str("node_id", nodeID).
			Str("file_path", filePath).
			Msg("🔍 [DIAGNOSTIC] GetKeyData: failed to read file")
		return nil, errors.Wrap(err, "failed to read encrypted key data")
	}

	log.Info().
		Str("key_id", keyID).
		Str("node_id", nodeID).
		Int("encrypted_size", len(encrypted)).
		Msg("🔍 [DIAGNOSTIC] GetKeyData: file read successfully, decrypting")

	// 解密数据
	keyData, err := s.decrypt(encrypted)
	if err != nil {
		log.Error().
			Err(err).
			Str("key_id", keyID).
			Str("node_id", nodeID).
			Int("encrypted_size", len(encrypted)).
			Msg("🔍 [DIAGNOSTIC] GetKeyData: decryption failed")
		return nil, errors.Wrap(err, "failed to decrypt key data")
	}

	log.Info().
		Str("key_id", keyID).
		Str("node_id", nodeID).
		Int("decrypted_size", len(keyData)).
		Msg("🔍 [DIAGNOSTIC] GetKeyData: decryption successful")

	return keyData, nil
}

// ValidateKeyShare 验证密钥分片格式（辅助函数）
func ValidateKeyShare(share []byte) error {
	// 基本验证：检查长度和格式
	if len(share) == 0 {
		return errors.New("key share is empty")
	}

	// 尝试解析为hex（如果分片是hex编码的）
	if _, err := hex.DecodeString(string(share)); err == nil {
		// 是hex编码，验证长度
		decoded, _ := hex.DecodeString(string(share))
		if len(decoded) < 32 {
			return fmt.Errorf("key share too short: %d bytes", len(decoded))
		}
	} else {
		// 不是hex编码，直接验证长度
		if len(share) < 32 {
			return fmt.Errorf("key share too short: %d bytes", len(share))
		}
	}

	return nil
}
