package keymgr

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"io"
	"os"
)

// 一个静态、硬编码的秘密，用作 Argon2id 的“password”参数。
// 这能确保在 Salt 已知的情况下，密钥派生过程是确定性的。
var argon2Password = []byte("gophantom-static-secret-for-derivation")

// Argon2id 参数。这些参数在生成器和加载器中必须保持一致。
const (
	argon2Time    = 1
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
	keyLength     = 32 // AES-256 需要 32 字节密钥
	saltLength    = 16 // 16 字节的 Salt
)

// DeriveKeyAndSalt 处理 Salt 的创建和主加密密钥的派生。
// 它会尝试从 GOPHANTOM_SALT 环境变量中读取 Base64 编码的 Salt。
// 如果变量不存在或无效，它将生成一个新的随机 Salt (弱随机回退)。
func DeriveKeyAndSalt() (key []byte, salt []byte, err error) {
	salt, err = getSaltFromEnv()
	if err != nil {
		// 回退机制: 如果环境变量缺失或无效，则生成一个新的随机 Salt
		fmt.Println("[!] GOPHANTOM_SALT env var not found or invalid. Falling back to random salt generation.")
		salt = make([]byte, saltLength)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, nil, fmt.Errorf("failed to generate random salt: %v", err)
		}
	} else {
		fmt.Println("[+] Successfully loaded 16-byte salt from GOPHANTOM_SALT env var.")
	}

	// 使用 Argon2id 派生密钥
	key = argon2.IDKey(argon2Password, salt, argon2Time, argon2Memory, argon2Threads, keyLength)
	return key, salt, nil
}

// getSaltFromEnv 从环境变量中读取 Salt。
func getSaltFromEnv() ([]byte, error) {
	saltB64 := os.Getenv("GOPHANTOM_SALT")
	if saltB64 == "" {
		return nil, fmt.Errorf("GOPHANTOM_SALT environment variable not set")
	}

	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt from base64: %v", err)
	}

	if len(salt) != saltLength {
		return nil, fmt.Errorf("salt must be %d bytes, but got %d", saltLength, len(salt))
	}
	return salt, nil
}
