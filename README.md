# GoPhantom

[![Go Version](https://img.shields.io/badge/Go-1.19%2B-blue.svg)](https://golang.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows-blue.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**GoPhantom** 是一个为红队演练和安全研究设计的下一代荷载加载器（Payload Loader）生成器。它利用 Go 语言的强大功能，将原始的 Shellcode 和一个诱饵文件打包成一个独立的、具有较强免杀（AV-Evasion）能力的 Windows 可执行文件。

## 核心功能 (Core Features)

### 🔐 加密与混淆
* **多层加密**: XOR + zlib压缩 + AES-256-GCM三重保护
* **动态密钥派生**: 使用Argon2id从随机Salt派生AES-256密钥，密钥本身永不存储
* **Shellcode变异**: 可选的代码变异功能，插入无害NOP指令破坏静态特征
* **睡眠混淆**: 程序睡眠期间使用随机密钥加密内存荷载，规避内存扫描

### 🛡️ 免杀技术  
* **内存权限分离**: 采用RW→RX内存操作模式，规避EDR行为检测
* **反沙箱检测**: 通过CPU核心数、物理内存、VM注册表等多维度检测分析环境
* **动态API解析**: 避免静态导入表暴露敏感API调用
* **行为伪装**: 执行前模拟正常程序行为模式

### 📦 实用功能
* **诱饵文件**: 支持PDF、图片、文档等格式，提高社工攻击成功率  
* **数据压缩**: zlib压缩可减少20-30%的文件体积
* **持久运行**: 程序稳定持续运行，不会自动退出或清理
* **纯Go实现**: 无CGO依赖，保证跨平台编译兼容性

## 使用方法 (Usage)

### 二进制版本使用

```bash
./GoPhantom-v1.3 -decoy <诱饵文件> -payload <荷载文件> -out <输出文件> [选项]

必需参数:
  -decoy     诱饵文件路径 (PDF、图片、文档等)
  -payload   x64 shellcode文件路径  
  -out       输出可执行文件名

可选参数:
  -compress  启用数据压缩 (默认: true)
  -obfuscate 启用睡眠混淆
  -mutate    启用shellcode变异
```

### 使用示例

基本加载器生成：
```bash
./GoPhantom-v1.3 -decoy "document.pdf" -payload "beacon.bin" -out "loader.exe"
```

完整功能加载器：
```bash
./GoPhantom-v1.3 -decoy "image.jpg" -payload "shell.bin" -out "advanced.exe" \
  -compress -obfuscate -mutate
```

### 源码编译

```bash
git clone https://github.com/watanabe-hsad/GoPhantom.git
cd GoPhantom
go build -ldflags "-s -w" -o GoPhantom-v1.3 generator.go
```

## 工作原理 (How it Works)

GoPhantom采用两阶段执行模式：**生成阶段**和**执行阶段**。

### 生成阶段 (Generator Phase)

在攻击机上运行生成器创建最终的加载器程序：

1. **数据预处理**: 读取shellcode和诱饵文件，进行XOR变换和zlib压缩
2. **Salt生成**: 自动生成16字节随机Salt(或从环境变量读取)
3. **密钥派生**: 使用Argon2id从Salt派生32字节AES-256密钥
4. **多层加密**: 使用派生密钥和AES-256-GCM算法加密处理后的数据
5. **模板注入**: 将加密数据和Salt以Base64格式嵌入Go加载器模板
6. **交叉编译**: 编译为windows/amd64平台的PE可执行文件

### 执行阶段 (Runtime Phase)

目标机器上的加载器执行流程：

1. **环境检测**: 执行反沙箱和反VM检测，不符合条件则退出
2. **行为伪装**: 模拟正常程序的启动行为模式
3. **密钥重建**: 从自身提取Salt，重新派生AES密钥
4. **数据解密**: 解密诱饵文件和shellcode数据
5. **诱饵展示**: 释放并打开诱饵文件转移用户注意力
6. **内存准备**: 申请RW权限内存，写入解密的shellcode
7. **可选处理**: 根据配置进行shellcode变异或睡眠混淆
8. **权限切换**: 将内存权限修改为RX，准备执行
9. **独立执行**: 创建新线程执行荷载，主进程立即退出

## 技术原理 (Technical Details)

### 加密流程
```
明文 → XOR变换 → zlib压缩 → AES-256-GCM加密 → Base64编码 → 嵌入模板
```

### 执行流程  
```
沙箱检测 → 行为伪装 → 解密诱饵文件 → 显示诱饵 → 
解密荷载 → [变异处理] → 内存执行 → 清理退出
```

### 反检测技术
- CPU核心数量验证
- 物理内存大小检查  
- 虚拟机注册表检测
- 磁盘空间分析
- 动态字符串反混淆

## 高级配置 (Advanced Configuration)

### 可复现构建模式

通过手动指定Salt实现可复现构建，确保相同输入生成相同输出：

**生成自定义Salt:**
```bash
# Linux/macOS/Git Bash
echo 'package main; import "crypto/rand"; import "encoding/base64"; import "fmt"; func main() { b := make([]byte, 16); _, _ = rand.Read(b); fmt.Println(base64.StdEncoding.EncodeToString(b)) }' > temp_salt.go && go run temp_salt.go && rm temp_salt.go

# Windows CMD/PowerShell  
echo 'package main; import "crypto/rand"; import "encoding/base64"; import "fmt"; func main() { b := make([]byte, 16); _, _ = rand.Read(b); fmt.Println(base64.StdEncoding.EncodeToString(b)) }' > temp_salt.go && go run temp_salt.go && del temp_salt.go
```

**使用自定义Salt:**
```bash
# Linux/macOS
export GOPHANTOM_SALT="y5M3H+e8vU/HeaJg2w9bEA=="
./GoPhantom-v1.3 -decoy "info.txt" -payload "calc_x64.bin" -out "reproducible.exe"

# Windows PowerShell
$env:GOPHANTOM_SALT="y5M3H+e8vU/HeaJg2w9bEA=="
./GoPhantom-v1.3 -decoy "info.txt" -payload "calc_x64.bin" -out "reproducible.exe"
```

### 运行时选项

**启用睡眠混淆:**
在目标机器执行前设置环境变量：
```powershell
# PowerShell
$env:GPH_OBFUS=1

# Bash  
export GPH_OBFUS=1
```

## 安装与使用 (Installation & Usage)

### 环境要求
* Go 1.19 或更高版本
* 支持交叉编译到Windows平台

### 快速开始

1. 克隆项目仓库：
   ```bash
   git clone https://github.com/watanabe-hsad/GoPhantom.git
   cd GoPhantom
   ```

2. 准备测试文件：
   - 将shellcode文件(如`beacon.bin`)放入项目目录
   - 准备诱饵文件(如`document.pdf`)

3. 生成加载器：
   ```bash
   # 源码方式
   go run generator.go -decoy "info.txt" -payload "calc_x64.bin" -out "hello.exe"
   
   # 二进制方式
   ./GoPhantom-v1.3 -decoy "info.txt" -payload "calc_x64.bin" -out "hello.exe"
   ```

### 使用模式

**简单模式 (默认)**
程序自动生成随机Salt，每次生成唯一加载器：
```bash
./GoPhantom-v1.3 -decoy "info.txt" -payload "calc_x64.bin" -out "hello.exe"
```

**可复现模式 (高级)**
指定固定Salt，实现可复现构建：
```bash
export GOPHANTOM_SALT="your-base64-salt-here"
./GoPhantom-v1.3 -decoy "info.txt" -payload "calc_x64.bin" -out "reproducible.exe"
```

## 演示截图 (Demo Screenshots)

### 生成过程
![生成过程](image/img_1.png)

### 免杀效果

![image-20250905114320905](image/img_2.png)

### 执行效果  

在目标Windows机器上执行生成的loader：
- 自动打开诱饵文件转移注意力
- 后台静默执行shellcode荷载

![执行效果](image/img.png)

## 项目结构 (Project Structure)

```
GoPhantom/
├── generator.go          # 主生成器程序
├── internal/
│   └── keymgr/
│       └── keymgr.go    # 密钥管理模块
├── image/               # 演示截图
├── *.bin               # 示例shellcode文件
├── *.exe               # 生成的加载器
└── README.md           # 项目文档
```

## 更新日志 (Changelog)

### v1.3.1 (当前版本)
- ✅ 移除自删除功能，提升程序稳定性
- ✅ 优化程序持久运行机制
- ✅ 修复进程自动退出问题

### v1.3
- ✅ 增强shellcode变异算法
- ✅ 优化睡眠混淆机制
- ✅ 改进反沙箱检测精度

### v1.2
- ✅ 新增睡眠混淆功能
- ✅ 支持shellcode变异
- ✅ 增强反VM检测

### v1.1  
- ✅ 引入Argon2id密钥派生
- ✅ 支持可复现构建
- ✅ 添加zlib数据压缩

## 免责声明 (Disclaimer)

⚠️ **此工具仅限于授权的渗透测试、安全研究和教育目的。**

严禁将此工具用于任何非法活动。本项目的作者不对任何因滥用或非法使用此工具而导致的直接或间接后果承担任何责任。用户应对自己的所有行为负责。

**使用本工具即表示您已阅读、理解并同意遵守此免责声明。**

---

## 支持项目 (Support)

如果这个项目对您有帮助，请考虑给个⭐Star支持一下！

有问题或建议？欢迎提交Issue或Pull Request。
