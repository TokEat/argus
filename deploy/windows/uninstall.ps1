# ==============================================================================
# Argus Windows 单机卸载脚本
#
# 默认仅停止服务与容器（数据保留在 data\，secrets.env 保留）。
# 加 -Purge 才会删除 data\（PostgreSQL/RabbitMQ/MinIO 全部数据，不可恢复）。
#
# 用法:
#   .\uninstall.ps1            # 停服务 + 停容器，保留数据
#   .\uninstall.ps1 -Purge     # 额外删除 data\ 与 PID/日志（需二次确认）
#   .\uninstall.ps1 -ComposeDown  # 停服务并 docker compose down（删除容器，保留卷目录）
# ==============================================================================

[CmdletBinding()]
param(
    [string]$BundleRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [switch]$Purge,
    [switch]$ComposeDown
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$DeployDir = Join-Path $BundleRoot "deploy"
$DataDir   = Join-Path $BundleRoot "data"
$SecretsPath = Join-Path $BundleRoot "secrets.env"
$PidPath     = Join-Path $DataDir "argus-services.json"
$ComposeFile = Join-Path $DeployDir "docker-compose.yml"

function Write-Ok([string]$msg)   { Write-Host "[✔] $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err([string]$msg)  { Write-Host "[✗] $msg" -ForegroundColor Red }

Write-Host "`n=== Argus Windows 卸载  根目录: $BundleRoot ===" -ForegroundColor Blue

# 1. 停止托管进程
if (Test-Path $PidPath) {
    $rec = Get-Content $PidPath -Raw | ConvertFrom-Json
    foreach ($name in @("server", "yaksha")) {
        $procId = $rec."$($name)Pid"
        if ($procId) {
            $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
            if ($proc) {
                Stop-Process -Id $procId -Force
                Write-Ok "已停止 $name (PID $procId)"
            }
        }
    }
    Remove-Item -Force $PidPath -ErrorAction SilentlyContinue
} else {
    Write-Warn "未找到 PID 记录，跳过进程停止（可用任务管理器手动结束 argus-server / yaksha）。"
}

# 2. NSSM 服务（若已注册）
foreach ($svc in @("argus-server", "argus-yaksha")) {
    $nssm = Get-Command nssm -ErrorAction SilentlyContinue
    if ($nssm) {
        $svcInfo = & nssm status $svc 2>$null
        if ($LASTEXITCODE -eq 0) {
            & nssm stop $svc 2>$null | Out-Null
            & nssm remove $svc confirm 2>$null | Out-Null
            Write-Ok "已移除 NSSM 服务 $svc"
        }
    }
}

# 3. 容器
if (Test-Path $ComposeFile) {
    if ($ComposeDown) {
        & docker compose --env-file $SecretsPath -f $ComposeFile down
        if ($LASTEXITCODE -eq 0) { Write-Ok "已 compose down（容器删除，data\ 卷目录保留）" }
    } else {
        & docker compose --env-file $SecretsPath -f $ComposeFile stop
        if ($LASTEXITCODE -eq 0) { Write-Ok "已停止基础设施容器（数据保留，可用 setup.ps1 重新拉起）" }
    }
} else {
    Write-Warn "未找到 compose 文件，跳过容器处理。"
}

# 4. 数据清理（需确认）
if ($Purge) {
    Write-Warn "即将永久删除 $DataDir（PostgreSQL/RabbitMQ/MinIO 全部数据，不可恢复）！"
    $confirm = Read-Host "输入 DELETE 确认删除数据目录"
    if ($confirm -eq "DELETE") {
        if (Test-Path $DataDir) {
            Remove-Item -Recurse -Force $DataDir
            Write-Ok "已删除 $DataDir"
        }
        Write-Warn "secrets.env 已保留（如需彻底清理请手动删除: $SecretsPath）"
    } else {
        Write-Warn "未输入 DELETE，数据目录保留。"
    }
} else {
    Write-Host "数据保留在: $DataDir（彻底删除请加 -Purge）"
}

Write-Ok "卸载流程结束。"
