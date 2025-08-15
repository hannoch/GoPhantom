package main

import (
	"fmt"
	"hash/crc32"
	"os"
)

// simpleCRC32Hash 计算字符串的 CRC32 哈希值
func simpleCRC32Hash(s string) uint32 {
	return crc32.ChecksumIEEE([]byte(s))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <string_to_hash>\n", os.Args[0])
		fmt.Println("Example: go run . VirtualAlloc")
		os.Exit(1)
	}

	input := os.Args[1]
	hash := simpleCRC32Hash(input)

	fmt.Printf("[+] String: %s\n", input)
	fmt.Printf("[+] CRC32 Hash: 0x%x\n", hash)
}
