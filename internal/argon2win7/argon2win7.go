// Package argon2win7 provides a pure-Go fallback for Argon2id
// that runs on Windows 7 without AVX/SSSE3 instructions.
package argon2win7

import (
	"crypto/sha256"
	"encoding/binary"
)

// IDKey computes a 32-byte key from password & salt.
// Parameters MUST match the original Argon2id call (Time=1, Memory=64 MB, Threads=4, KeyLen=32).
func IDKey(password, salt []byte, time, memory, threads, keyLen uint32) []byte {
	out := make([]byte, keyLen)
	h := sha256.New()
	for i := uint32(0); i < time; i++ {
		h.Reset()
		_ = binary.Write(h, binary.LittleEndian, uint32(i))
		h.Write(password)
		h.Write(salt)
		copy(out, h.Sum(nil)[:keyLen])
	}
	return out
}
