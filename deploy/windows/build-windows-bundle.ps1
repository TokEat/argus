# ==============================================================================
# Argus Windows 部署包打包脚本（开发机执行）
#
# 一键产出可在 Windows 机器上解压即用的单机部署包：
#   argus-windows-amd64-<版本>.zip
#
# 自动执行：
#   1. 交叉编译 windows/amd64：argus / argus-agent / argus-server
#   2. 构建前端 server-ui/dist
#   3. 生成预编译规则资产库 deploy/arsenal_seed.db（POC/指纹/工作流）
#   4. 构建 yaksha OCI 镜像并 docker save（yaksha 依赖 cgo libpcre2，
#      仅 Linux 二进制，Windows 上以容器方式运行，需本机 Docker）
#   5. 组装目录结构并压缩为 zip
#
# 用法（在仓库根目录执行）:
#   .\deploy\windows\build-windows-bundle.ps1                 # 默认 v0.1.0
#   .\deploy\windows\build-windows-bundle.ps1 -Version v0.1.1
#   .\deploy\windows\build-windows-bundle.ps1 -SkipFrontend   # 复用已有 server-ui/dist
#   .\deploy\windows\build-windows-bundle.ps1 -SkipYakshaImage # 复用已有 argus-yaksha:local 镜像
#
# 依赖：go（>=1.25）、Node.js 18+（npm）、PowerShell 5.1+、Docker（仅 yaksha 镜像步骤）。
# 产物输出到仓库根目录 release\argus-windows-amd64-<版本>.zip。
# ==============================================================================

[CmdletBinding()]
param(
    [string]$Version = "v0.1.0",
    [switch]$SkipFrontend,
    [switch]$SkipYakshaImage
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not ($Version -match "^v[0-9]+(\.[0-9]+){2}([-.][0-9A-Za-z.-]+)?$")) {
    Write-Host "Invalid release version: $Version; expected vMAJOR.MINOR.PATCH" -ForegroundColor Red
    exit 2
}

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $RootDir

$BundleName = "argus-windows-amd64-$Version"
$StageDir   = Join-Path $RootDir "release\$BundleName"
$ReleaseDir = Join-Path $RootDir "release"

function Write-Step([string]$msg) { Write-Host "`n=== $msg ===" -ForegroundColor Blue }
function Write-Ok([string]$msg)   { Write-Host "[✔] $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err([string]$msg)  { Write-Host "[✗] $msg" -ForegroundColor Red; exit 1 }

Write-Step "Argus Windows 部署包打包  版本: $Version"

# 1. 交叉编译 windows/amd64 全部组件
Write-Step "[1/5] 交叉编译 windows/amd64（argus / argus-agent / argus-server）"
if (-not (Get-Command go -ErrorAction SilentlyContinue)) { Write-Err "未找到 go" }
& .\build.ps1 -Component argus,argus-agent,argus-server -Target windows/amd64
if ($LASTEXITCODE -ne 0) { Write-Err "交叉编译失败" }

$built = @{
    "argus"        = Join-Path $ReleaseDir "argus-windows-amd64.exe"
    "argus-agent"  = Join-Path $ReleaseDir "argus-agent-windows-amd64.exe"
    "argus-server" = Join-Path $ReleaseDir "argus-server-windows-amd64.exe"
}
foreach ($k in $built.Keys) {
    if (-not (Test-Path $built[$k])) { Write-Err "缺少编译产物: $($built[$k])" }
}
Write-Ok "交叉编译完成"

# 2. 前端
if (-not $SkipFrontend) {
    Write-Step "[2/4] 构建前端控制台（server-ui/dist）"
    Push-Location (Join-Path $RootDir "server-ui")
    try {
        npm ci
        if ($LASTEXITCODE -ne 0) { throw "npm ci 失败" }
        npm run build
        if ($LASTEXITCODE -ne 0) { throw "npm run build 失败" }
    } finally {
        Pop-Location
    }
} else {
    Write-Warn "[2/4] 按 -SkipFrontend 复用已有 server-ui/dist"
}
if (-not (Test-Path (Join-Path $RootDir "server-ui\dist\index.html"))) {
    Write-Err "前端产物缺失: server-ui\dist\index.html"
}
Write-Ok "前端产物就绪"

# 3. 规则资产库
Write-Step "[3/4] 生成预编译规则资产库 deploy\arsenal_seed.db"
Push-Location $RootDir
try {
    go run .\server\scripts\build_seed_db.go
    if ($LASTEXITCODE -ne 0) { throw "build_seed_db 失败" }
} finally {
    Pop-Location
}
if (-not (Test-Path (Join-Path $RootDir "deploy\arsenal_seed.db"))) {
    Write-Err "规则资产库生成失败"
}
Write-Ok "arsenal_seed.db 就绪"

# 3.5 yaksha OCI 镜像（Linux-only，docker save 进包）
if (-not $SkipYakshaImage) {
    Write-Step "[3.5/5] 构建 yaksha 镜像"
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Write-Err "未找到 docker（构建 yaksha 镜像需要）" }
    & docker build --platform linux/amd64 -f (Join-Path $RootDir "yaksha\Dockerfile") -t argus-yaksha:local $RootDir
    if ($LASTEXITCODE -ne 0) { Write-Err "yaksha 镜像构建失败" }
} else {
    Write-Warn "[3.5/5] 按 -SkipYakshaImage 复用已有 argus-yaksha:local 镜像"
}

# 4. 组装 + 压缩
Write-Step "[4/5] 组装部署包并压缩"
if (Test-Path $StageDir) { Remove-Item -Recurse -Force $StageDir }
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir "bin") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir "deploy\db-init") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir "deploy\images") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir "server-ui") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir "release") | Out-Null

& docker save -o (Join-Path $StageDir "deploy\images\argus-yaksha.tar") argus-yaksha:local
if ($LASTEXITCODE -ne 0) { Write-Err "docker save yaksha 失败" }
Write-Ok "yaksha 镜像归档就绪"

# 二进制（统一短名，setup.ps1 依赖此命名）
Copy-Item $built["argus-server"] (Join-Path $StageDir "bin\argus-server.exe")
Copy-Item $built["argus-agent"]  (Join-Path $StageDir "bin\argus-agent.exe")
Copy-Item $built["argus"]        (Join-Path $StageDir "bin\argus.exe")
# CLI 离线弹药库（与 argus.exe 同目录，首次运行自动导入）
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir "bin\argus-data\arsenal") | Out-Null
Copy-Item (Join-Path $ReleaseDir ".arsenal-package\arsenal.db") (Join-Path $StageDir "bin\argus-data\arsenal\arsenal.db")
# Agent 二进制分发目录（/release 静态路由，OSS fallback）
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir "release") | Out-Null
Copy-Item $built["argus-agent"] (Join-Path $StageDir "release\argus-agent-windows-amd64.exe")

# 规则配置（finger.yaml / dir.yaml / workflow.yaml / pocs / dict ...）
Copy-Item -Recurse (Join-Path $RootDir "config") (Join-Path $StageDir "config")

# 前端
Copy-Item -Recurse (Join-Path $RootDir "server-ui\dist") (Join-Path $StageDir "server-ui\dist")

# 部署资产
Copy-Item (Join-Path $RootDir "deploy\arsenal_seed.db") (Join-Path $StageDir "deploy\arsenal_seed.db")
Copy-Item (Join-Path $PSScriptRoot "docker-compose.yml") (Join-Path $StageDir "deploy\docker-compose.yml")
Copy-Item (Join-Path $PSScriptRoot "setup.ps1")          (Join-Path $StageDir "deploy\setup.ps1")
Copy-Item (Join-Path $PSScriptRoot "uninstall.ps1")      (Join-Path $StageDir "deploy\uninstall.ps1")
Copy-Item (Join-Path $PSScriptRoot "README.md")          (Join-Path $StageDir "README.md")
# 数据库初始化 SQL（postgres 首次启动自动执行）
Copy-Item (Join-Path $RootDir "deploy\db\init\*.sql") (Join-Path $StageDir "deploy\db-init\")

$required = @(
    "bin\argus-server.exe", "bin\argus-agent.exe", "bin\argus.exe",
    "bin\argus-data\arsenal\arsenal.db",
    "config\finger.yaml", "config\dir.yaml", "config\workflow.yaml",
    "server-ui\dist\index.html",
    "deploy\arsenal_seed.db", "deploy\docker-compose.yml",
    "deploy\images\argus-yaksha.tar",
    "deploy\setup.ps1", "deploy\uninstall.ps1",
    "deploy\db-init\001_init.sql", "deploy\db-init\seed_admin.sql",
    "README.md"
)
foreach ($rel in $required) {
    if (-not (Test-Path (Join-Path $StageDir $rel))) { Write-Err "部署包缺少必需文件: $rel" }
}
Write-Ok "目录结构校验通过（含 $(@(Get-ChildItem (Join-Path $StageDir 'deploy\db-init\*.sql')).Count) 个数据库迁移脚本）"

$zipFile = Join-Path $ReleaseDir "$BundleName.zip"
if (Test-Path $zipFile) { Remove-Item -Force $zipFile }
Compress-Archive -Path $StageDir -DestinationPath $zipFile -CompressionLevel Optimal
Remove-Item -Recurse -Force $StageDir

$zipSize = (Get-Item $zipFile).Length
Write-Step "打包完成"
Write-Host "  产物: $zipFile" -ForegroundColor Green
Write-Host ("  大小: {0:N1} MB" -f ($zipSize / 1MB)) -ForegroundColor Green
Write-Host ""
Write-Host "  部署步骤（目标 Windows 机器）：" -ForegroundColor Blue
Write-Host "    1. 解压 zip 到任意目录（如 C:\argus）"
Write-Host "    2. 确认 Docker Desktop 已启动"
Write-Host "    3. 执行:  deploy\setup.ps1"
Write-Host "    4. 浏览器访问 http://127.0.0.1:8085 （admin / 首次登录改密）"
