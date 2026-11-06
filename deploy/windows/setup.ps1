# ==============================================================================
# Argus Windows 单机一键部署脚本
#
# 职责（与 Linux deploy/setup-server.sh 对齐）：
#   1. 生成/复用 secrets.env（所有随机密钥唯一事实来源）
#   2. 加载并启动基础设施容器（PostgreSQL + RabbitMQ + MinIO + yaksha，
#      首次自动建库/迁移；yaksha 为 Linux-only 二进制，仅容器方式可用）
#   3. 导入预编译规则资产库（POC/指纹/工作流，--seed-from-db，幂等 upsert）
#   4. 以原生 Windows 进程启动 argus-server（工作目录 = 包根目录）
#
# 用法（在包根目录的 deploy\ 下执行，或任意目录以 -BundleRoot 指定）：
#   .\setup.ps1                 # 完整安装（基础设施 + POC 导入 + 启动服务）
#   .\setup.ps1 -SeedOnly       # 只重新导入规则资产（不启动容器/服务）
#   .\setup.ps1 -Stop           # 停止 argus-server（保留容器与数据）
#   .\setup.ps1 -SkipSeed       # 跳过 POC 导入（已导入过且规则库未更新时）
#
# 前置条件：Docker Desktop（WSL2 后端）已安装并运行；双击本脚本请以普通用户
# 运行即可（仅绑定高端口，无需管理员）。注册为系统服务请用 -InstallService。
# ==============================================================================

[CmdletBinding()]
param(
    [string]$BundleRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [switch]$SeedOnly,
    [switch]$SkipSeed,
    [switch]$Stop,
    [switch]$InstallService
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$DeployDir = Join-Path $BundleRoot "deploy"
$BinDir    = Join-Path $BundleRoot "bin"
$DataDir   = Join-Path $BundleRoot "data"
$LogDir    = Join-Path $DataDir "logs"
$SecretsPath = Join-Path $BundleRoot "secrets.env"
$PidPath     = Join-Path $DataDir "argus-services.json"

$ServerExe  = Join-Path $BinDir "argus-server.exe"
$SeedDb     = Join-Path $DeployDir "arsenal_seed.db"
$YakshaImage = Join-Path $DeployDir "images\argus-yaksha.tar"
$ComposeFile = Join-Path $DeployDir "docker-compose.yml"

function Write-Step([string]$msg) { Write-Host "`n=== $msg ===" -ForegroundColor Blue }
function Write-Ok([string]$msg)   { Write-Host "[✔] $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err([string]$msg)  { Write-Host "[✗] $msg" -ForegroundColor Red }

function New-RandomBase64([int]$bytes = 32) {
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $buf = New-Object byte[] $bytes
    $rng.GetBytes($buf)
    $rng.Dispose()
    return [Convert]::ToBase64String($buf)
}

function New-RandomToken([int]$len = 24) {
    $alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $buf = New-Object byte[] ($len * 2)
    $rng.GetBytes($buf)
    $rng.Dispose()
    $chars = New-Object char[] $len
    for ($i = 0; $i -lt $len; $i++) {
        $chars[$i] = $alphabet[$buf[$i * 2] % $alphabet.Length]
    }
    return -join $chars
}

function Import-SecretsEnv {
    if (-not (Test-Path $SecretsPath)) { return }
    Get-Content $SecretsPath | ForEach-Object {
        $line = $_.Trim()
        if ($line -eq "" -or $line.StartsWith("#")) { return }
        $idx = $line.IndexOf("=")
        if ($idx -le 0) { return }
        $key = $line.Substring(0, $idx).Trim()
        $val = $line.Substring($idx + 1).Trim()
        Set-Item -Path "Env:$key" -Value $val
    }
}

function Save-SecretsEnv([hashtable]$map) {
    $lines = @(
        "# Argus Windows 单机部署密钥（自动生成，唯一事实来源）",
        "# 权限建议：仅当前用户可读。泄露任一密钥后请轮换并重启服务。",
        "# 本文件同时供 docker compose（--env-file）与 setup.ps1 启动服务使用。"
    )
    foreach ($key in ($map.GetEnumerator() | Sort-Object Name)) {
        $lines += "$($key.Name)=$($key.Value)"
    }
    [System.IO.File]::WriteAllLines($SecretsPath, $lines)
    Write-Warn "secrets.env 已生成/更新：$SecretsPath"
}

function Ensure-Secrets {
    $map = @{}
    if (Test-Path $SecretsPath) {
        Get-Content $SecretsPath | ForEach-Object {
            $line = $_.Trim()
            if ($line -eq "" -or $line.StartsWith("#")) { return }
            $idx = $line.IndexOf("=")
            if ($idx -le 0) { return }
            $map[$line.Substring(0, $idx).Trim()] = $line.Substring($idx + 1).Trim()
        }
    }
    $defaults = [ordered]@{
        "POSTGRES_USER"               = "postgres"
        "POSTGRES_PASSWORD"           = (New-RandomToken 32)
        "POSTGRES_DB"                 = "argus"
        "POSTGRES_PORT"               = "5432"
        "RABBITMQ_DEFAULT_USER"       = "argus"
        "RABBITMQ_DEFAULT_PASS"       = (New-RandomToken 32)
        "RABBITMQ_PORT"               = "5672"
        "RABBITMQ_MANAGEMENT_PORT"    = "15672"
        "MINIO_ROOT_USER"             = "argus-minio"
        "MINIO_ROOT_PASSWORD"         = (New-RandomToken 32)
        "MINIO_API_PORT"              = "9000"
        "MINIO_CONSOLE_PORT"          = "9001"
        "ARGUS_EXP_MINIO_ACCESS_KEY"  = (New-RandomToken 20)
        "ARGUS_EXP_MINIO_SECRET_KEY"  = (New-RandomToken 40)
        "ARGUS_EXP_MINIO_BUCKET"      = "argus-exp"
        "ARGUS_JWT_SECRET"            = (New-RandomBase64 32)
        "ARGUS_AGENT_PSK"             = (New-RandomToken 32)
        "ARGUS_CREDENTIAL_ENCRYPT_KEY" = (New-RandomBase64 32)
        "ARGUS_ENCRYPT_KEY"           = (New-RandomBase64 32)
    }
    $changed = $false
    foreach ($key in $defaults.Keys) {
        if (-not $map.ContainsKey($key) -or $map[$key] -eq "") {
            $map[$key] = $defaults[$key]
            $changed = $true
        }
    }
    if ($changed -or -not (Test-Path $SecretsPath)) {
        Save-SecretsEnv $map
    }
    # 载入当前进程，供 compose 与服务启动使用
    Import-SecretsEnv
    return $map
}

function Get-Dsn {
    return "host=127.0.0.1 user=$env:POSTGRES_USER password=$env:POSTGRES_PASSWORD dbname=$env:POSTGRES_DB port=$env:POSTGRES_PORT sslmode=disable"
}

function Stop-ArgusProcesses {
    if (-not (Test-Path $PidPath)) {
        Write-Warn "未找到 PID 记录（$PidPath），无已托管进程。"
        return
    }
    $rec = Get-Content $PidPath -Raw | ConvertFrom-Json
    foreach ($name in @("server")) {
        $pidField = "$($name)Pid"
        $procId = $rec.$pidField
        if ($procId) {
            $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
            if ($proc) {
                Stop-Process -Id $procId -Force
                Write-Ok "已停止 $name (PID $procId)"
            }
        }
    }
    Remove-Item -Force $PidPath -ErrorAction SilentlyContinue
}

function Wait-HttpReady([string]$url, [int]$timeoutSec = 120, [string]$name = "服务") {
    Write-Host -NoNewline "等待 $name 就绪 ($url)"
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5
            if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 500) {
                Write-Host ""
                return $true
            }
        } catch {
            $code = $null
            if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
            if ($code -and $code -ge 200 -and $code -lt 500) {
                Write-Host ""
                return $true
            }
        }
        Write-Host -NoNewline "."
        Start-Sleep -Seconds 2
    }
    Write-Host ""
    return $false
}

function Wait-PostgresReady([int]$timeoutSec = 180) {
    Write-Host -NoNewline "等待 PostgreSQL 就绪"
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        & docker compose --env-file $SecretsPath -f $ComposeFile exec -T postgres `
            pg_isready -U $env:POSTGRES_USER -d $env:POSTGRES_DB 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host ""
            return $true
        }
        Write-Host -NoNewline "."
        Start-Sleep -Seconds 3
    }
    Write-Host ""
    return $false
}

function Invoke-SeedImport {
    Write-Step "[4/5] 导入规则资产库（POC / 指纹 / 工作流）"
    if ($SkipSeed) {
        Write-Warn "按 -SkipSeed 跳过规则导入。"
        return
    }
    if (-not (Test-Path $SeedDb)) {
        Write-Err "未找到规则资产库: $SeedDb"
        exit 1
    }
    # seed 进程同样会初始化 EXP 工作区（MinIO）并要求 yaksha 就绪，
    # 因此 -SeedOnly 前需确保容器已启动。
    if ($SeedOnly) {
        Write-Warn "-SeedOnly 模式：假定 PostgreSQL / MinIO / yaksha 容器已在运行。"
    }
    Import-SecretsEnv
    $env:ARGUS_EXP_MINIO_ENDPOINT = "http://127.0.0.1:$env:MINIO_API_PORT"
    $env:ARGUS_EXP_MINIO_REGION = "us-east-1"
    $env:ARGUS_EXP_MINIO_USE_SSL = "false"
    $env:ARGUS_YAKSHA_URL = "http://127.0.0.1:8790"
    $dsn = Get-Dsn
    & $ServerExe --db $dsn --seed-from-db $SeedDb
    if ($LASTEXITCODE -ne 0) {
        Write-Err "规则资产导入失败（幂等 upsert，可直接重跑本脚本）。"
        exit 1
    }
    Write-Ok "规则资产导入完成（重复导入仅更新有变化的规则）"
}

# ------------------------------- 入口 -------------------------------

if ($Stop) {
    Write-Step "停止 Argus 服务（保留容器与数据）"
    Stop-ArgusProcesses
    Write-Ok "已停止。停止基础设施容器请执行: docker compose --env-file ..\secrets.env -f docker-compose.yml stop"
    exit 0
}

Write-Step "Argus Windows 单机部署  根目录: $BundleRoot"

# 1. 前置检查
Write-Step "[1/5] 前置检查"
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Err "未找到 docker。请先安装 Docker Desktop（WSL2 后端）并启动。"
    exit 1
}
& docker compose version 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Err "docker compose v2 不可用，请升级 Docker Desktop。"
    exit 1
}
foreach ($f in @($ServerExe, $SeedDb, $ComposeFile)) {
    if (-not (Test-Path $f)) {
        Write-Err "缺少必需文件: $f （请使用 deploy\windows\build-windows-bundle.ps1 生成完整部署包）"
        exit 1
    }
}
Write-Ok "Docker 与部署文件检查通过"

# 2. 密钥
Write-Step "[2/5] 生成/复用 secrets.env"
$secrets = Ensure-Secrets
Write-Ok "密钥就绪（$SecretsPath）"

if ($SeedOnly) {
    Ensure-Secrets | Out-Null
    Invoke-SeedImport
    exit 0
}

# 3. 基础设施容器
Write-Step "[3/5] 启动基础设施容器（PostgreSQL / RabbitMQ / MinIO / yaksha）"
# yaksha 镜像（Linux-only，打包时 docker save；目标机首次启动 load）
& docker image inspect argus-yaksha:local 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    if (-not (Test-Path $YakshaImage)) {
        Write-Err "缺少 yaksha 镜像归档: $YakshaImage"
        exit 1
    }
    Write-Host "加载 yaksha 镜像..."
    & docker load -i $YakshaImage
    if ($LASTEXITCODE -ne 0) { Write-Err "docker load yaksha 镜像失败" }
}
Push-Location $DeployDir
try {
    & docker compose --env-file $SecretsPath -f $ComposeFile up -d
    if ($LASTEXITCODE -ne 0) { throw "docker compose up 失败" }
} finally {
    Pop-Location
}
if (-not (Wait-PostgresReady)) {
    Write-Err "PostgreSQL 在超时时间内未就绪，请检查: docker compose -f $ComposeFile logs postgres"
    exit 1
}
Write-Ok "PostgreSQL 就绪（首次启动已自动执行 db-init 迁移）"
if (-not (Wait-HttpReady "http://127.0.0.1:8790/readyz" 120 "yaksha")) {
    Write-Err "yaksha 在超时时间内未就绪，请检查: docker compose -f $ComposeFile logs yaksha"
    exit 1
}
Write-Ok "yaksha 就绪（EXP 沙箱运行时）"

# 4. POC / 规则资产导入
Invoke-SeedImport

# 5. 启动 argus-server
Write-Step "[5/5] 启动 argus-server"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Import-SecretsEnv
if (Test-Path $PidPath) {
    Write-Warn "检测到已托管的服务进程，先停止旧实例再启动。"
    Stop-ArgusProcesses
}

$env:ARGUS_YAKSHA_URL = "http://127.0.0.1:8790"
$env:ARGUS_EXP_MINIO_ENDPOINT = "http://127.0.0.1:$($secrets["MINIO_API_PORT"])"
$env:ARGUS_EXP_MINIO_REGION = "us-east-1"
$env:ARGUS_EXP_MINIO_USE_SSL = "false"

$configDir = Join-Path $BundleRoot "config"
$amqpUrl = "amqp://${env:RABBITMQ_DEFAULT_USER}:${env:RABBITMQ_DEFAULT_PASS}@127.0.0.1:$env:RABBITMQ_PORT/"
$serverArgs = @(
    "--db", (Get-Dsn),
    "--config-dir", "`"$configDir`"",
    "--amqp", "`"$amqpUrl`"",
    "--api", ":8085",
    "--grpc", ":50051",
    "--deploy-mode", "intranet"
)
$server = Start-Process -FilePath $ServerExe `
    -WorkingDirectory $BundleRoot `
    -ArgumentList $serverArgs `
    -RedirectStandardOutput (Join-Path $LogDir "argus-server.log") `
    -RedirectStandardError (Join-Path $LogDir "argus-server.err.log") `
    -WindowStyle Hidden -PassThru
Write-Ok "argus-server 已启动 (PID $($server.Id))，日志: data\logs\argus-server.log"

@{
    serverPid = $server.Id
    startedAt = (Get-Date).ToString("o")
} | ConvertTo-Json | Set-Content -Path $PidPath -Encoding UTF8

if ($InstallService) {
    Write-Warn "-InstallService: 请使用 NSSM 将上述进程注册为 Windows 服务（见 README.md 第 5 节），当前会话以 PID 方式托管。"
}

# 6. 汇总
$lanIP = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notmatch "^(127\.|169\.254\.)" -and $_.PrefixOrigin -ne "WellKnown" } |
    Select-Object -First 1).IPAddress
if (-not $lanIP) { $lanIP = "<本机IP>" }

Write-Step "部署完成"
Write-Host "  控制台:   http://127.0.0.1:8085  （默认账号 admin，首次登录后请立即改密）"
Write-Host "  Agent 接入: -server ${lanIP}:50051  -api http://${lanIP}:8085  -psk <见 secrets.env 的 ARGUS_AGENT_PSK>"
Write-Host "  密钥文件: $SecretsPath"
Write-Host "  管理命令: .\setup.ps1 -Stop 停止服务；docker compose -f $ComposeFile stop 停容器"
