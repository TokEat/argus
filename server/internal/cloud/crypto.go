package cloud

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
)

// ============================================================================
// 凭证加解密层 — AES-256-GCM
//
// 用于保护 cloud_accounts 表中的 AccessKey ID / Secret。
// 密钥来源优先级:
//   1. 环境变量 ARGUS_ENCRYPT_KEY (生产环境必须配置，Base64 编码的 32 字节密钥)
//   2. 固定 fallback 密钥 (仅开发环境，启动时输出警告)
// ============================================================================

const (
	envKeyName    = "ARGUS_ENCRYPT_KEY"
	// 开发环境降级密钥 — 固定 32 字节，仅用于本地开发，生产环境绝不应使用
	devFallbackKey = "argus-dev-encrypt-key-do-not-use"
)

var (
	encryptKey     []byte
	encryptKeyOnce sync.Once
)

// resolveEncryptKey 懒加载加密密钥，只解析一次。
func resolveEncryptKey() []byte {
	encryptKeyOnce.Do(func() {
		raw := os.Getenv(envKeyName)
		if raw != "" {
			// 尝试 Base64 解码
			decoded, err := base64.StdEncoding.DecodeString(raw)
			if err == nil && len(decoded) == 32 {
				encryptKey = decoded
				log.Printf("[Crypto] Encryption key loaded from %s (base64, 256-bit)", envKeyName)
				return
			}
			// 如果不是有效的 Base64 或长度不对，尝试直接作为 raw bytes
			if len(raw) == 32 {
				encryptKey = []byte(raw)
				log.Printf("[Crypto] Encryption key loaded from %s (raw, 256-bit)", envKeyName)
				return
			}
			log.Printf("[Crypto] WARNING: %s is set but not a valid 256-bit key (got %d bytes), falling back to dev key", envKeyName, len(raw))
		}

		// 开发环境降级
		encryptKey = []byte(devFallbackKey)
		log.Printf("[Crypto] ⚠️  WARNING: Using development fallback encryption key. Set %s in production!", envKeyName)
	})
	return encryptKey
}

// EncryptSecret 使用 AES-256-GCM 加密明文，返回 Base64 编码的密文 (nonce + ciphertext)。
func EncryptSecret(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	key := resolveEncryptKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	// nonce 前置于密文
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptSecret 解密 EncryptSecret 产出的 Base64 密文，返回明文。
func DecryptSecret(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	key := resolveEncryptKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	return string(plaintext), nil
}

// MaskSecret 对凭证字符串进行脱敏，用于 API 返回。
// 保留前 4 位和后 4 位，中间用 **** 替代。
func MaskSecret(secret string) string {
	if len(secret) <= 8 {
		return "****"
	}
	return secret[:4] + "****" + secret[len(secret)-4:]
}
