//go:build win7
// +build win7

package keymgr

import "GoPhantom/internal/argon2win7"

// IDKey forwards to the pure-Go implementation on Windows 7.
func IDKey(password, salt []byte, time, memory, threads, keyLen uint32) []byte {
	return argon2win7.IDKey(password, salt, time, memory, threads, keyLen)
}
