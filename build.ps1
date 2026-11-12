# ==============================================================================
# Argus Windows 构建脚本 (PowerShell)
#
# 本机当前架构 -> bin\（日常开发）
# 交叉编译     -> release\（发行、多平台）
#
#   .\build.ps1                 # cli + agent + server，当前机器
#   .\build.ps1 agent
#   .\build.ps1 cli
#   .\build.ps1 server
#   .\build.ps1 mcp
#   .\build.ps1 yaksha
#   .\build.ps1 agent -Target linux/amd64
#   .\build.ps1 -Component argus-agent -Target darwin/arm64
#   .\build.ps1 cross           # 全平台交叉编译
#
# 参数:
#   -Pack                    启用 UPX 压缩（需本机安装 upx；darwin 会跳过）
#   -RequireUpx              UPX 缺失或失败时直接终止
#   -Component <list>        组件：argus, argus-agent, argus-server（逗号分隔，可配合别名 cli/agent/server）
#   -Target <list>           平台：darwin/arm64, linux-amd64, windows/amd64（逗号分隔）
#   -AllTargets / cross      编译全部支持的 OS/Arch 到 release\
#   -List                    展示可用组件、平台和当前机器
#   -Help                    显示帮助
#
# 产物约定:
#   bin\      当前机器可执行文件（无架构后缀），供本地直接运行
#   release\  交叉编译产物，文件名带 <os>-<arch>；CLI 额外产出 <os>-<arch>.zip 离线包
# ==============================================================================

[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Positionals = @(),
    [string]$Component = "",
    [string]$Target = "",
    [switch]$AllTargets,
    [switch]$Pack,
    [switch]$RequireUpx,
    [switch]$List,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RootDir

$BinDir = "bin"
$ReleaseDir = "release"

# 组件表: name -> @{ Path=main_path; Tags=build_tags }
# 本机 CLI 使用内嵌规则（清空 tags）；交叉编译 CLI 使用 noembed + 离线包
$Components = @{
    "argus"        = @{ Path = "./scanner/cmd/cli";    Tags = "noembed" }
    "argus-agent"  = @{ Path = "./scanner/cmd/agent";  Tags = "noembed" }
    "argus-server" = @{ Path = "./server/cmd/argus-server"; Tags = "" }
}

$Targets = @(
    "darwin:amd64",
    "darwin:arm64",
    "linux:amd64",
    "linux:arm64",
    "windows:amd64",
    "windows:arm64",
    "windows:386"
)

function Write-Info([string]$msg)    { Write-Host $msg -ForegroundColor Blue }
function Write-Ok([string]$msg)      { Write-Host $msg -ForegroundColor Green }
function Write-Warn([string]$msg)    { Write-Host $msg -ForegroundColor Yellow }
function Write-Err([string]$msg)     { Write-Host $msg -ForegroundColor Red }

function Show-Help {
    @"
Argus Windows build script

本机当前架构（输出 bin\）:
  .\build.ps1                 cli + agent + server
  .\build.ps1 agent
  .\build.ps1 cli
  .\build.ps1 server
  .\build.ps1 mcp
  .\build.ps1 yaksha

交叉编译（输出 release\）:
  .\build.ps1 cross
  .\build.ps1 agent -Target linux/amd64
  .\build.ps1 -Component argus-agent -Target darwin/arm64

Options:
  -Pack                    启用 UPX 压缩（需本机安装 upx；darwin 会跳过）
  -RequireUpx              UPX 缺失或失败时直接终止
  -Component <list>        组件：argus, argus-agent, argus-server（可逗号分隔）
  -Target <list>           平台：darwin/arm64, linux:amd64, windows-amd64
  -AllTargets, cross       编译全部支持的 OS/Arch 到 release\
  -List                    展示可用组件、平台和当前机器
  -Help                    显示帮助

产物约定:
  bin\      当前机器可执行文件（无架构后缀），供本地直接运行
  release\  交叉编译产物，文件名带 <os>-<arch>；CLI 额外产出 zip 离线包
"@
}

function Get-HostTarget {
    $os = (& go env GOOS).Trim()
    $arch = (& go env GOARCH).Trim()
    if (-not $os -or -not $arch) {
        Write-Err "[!] 无法识别当前机器架构（go env GOOS/GOARCH 为空）"
        exit 1
    }
    return "${os}:${arch}"
}

function Show-Supported {
    $hostTgt = Get-HostTarget
    Write-Info ("当前机器: " + $hostTgt.Replace(":", "/"))
    Write-Info "可用组件:"
    Write-Host "  - cli          (argus)"
    Write-Host "  - agent        (argus-agent)"
    Write-Host "  - server       (argus-server)"
    Write-Host "  - mcp          (argus-mcp)"
    Write-Host "  - yaksha"
    Write-Info "可用平台:"
    foreach ($t in $Targets) {
        Write-Host "  - $($t.Replace(':','/'))"
    }
}

function ConvertTo-CanonicalTarget([string]$raw) {
    return ($raw -replace "[-/]", ":").Trim().ToLowerInvariant()
}

function Resolve-ComponentName([string]$alias) {
    switch -Regex ($alias.Trim().ToLowerInvariant()) {
        "^(cli|argus)$"           { return "argus" }
        "^(agent|argus-agent)$"   { return "argus-agent" }
        "^(server|argus-server)$" { return "argus-server" }
        "^(mcp|argus-mcp)$"       { return "argus-mcp" }
        "^yaksha$"                { return "yaksha" }
        default                   { return "" }
    }
}

function Test-IsSupportedTarget([string]$target) {
    return $Targets -contains $target
}

function Get-OutputName([string]$name, [string]$os, [string]$arch, [bool]$localMode) {
    if ($localMode) {
        $out = Join-Path $BinDir $name
    } else {
        $out = Join-Path $ReleaseDir "$name-${os}-${arch}"
    }
    if ($os -eq "windows") {
        $out = "$out.exe"
    }
    return $out
}

function Invoke-GoBuild([string]$path, [string]$os, [string]$arch, [string]$outFile, [string]$tags) {
    $env:CGO_ENABLED = "0"
    $env:GOOS = $os
    $env:GOARCH = $arch
    try {
        $argsList = @("build", "-ldflags=-s -w", "-trimpath", "-o", $outFile)
        if ($tags) {
            $argsList += @("-tags", $tags)
        }
        $argsList += $path
        & go @argsList
        return ($LASTEXITCODE -eq 0)
    } finally {
        Remove-Item Env:GOOS -ErrorAction SilentlyContinue
        Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
        Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
    }
}

function Invoke-NestedBuild([string]$dir, [string]$outFile, [string]$package, [string]$os, [string]$arch, [bool]$goWorkOff) {
    Push-Location $dir
    try {
        $env:CGO_ENABLED = "0"
        $env:GOOS = $os
        $env:GOARCH = $arch
        if ($goWorkOff) {
            $env:GOWORK = "off"
        }
        $dest = Join-Path $RootDir $outFile
        & go build -ldflags="-s -w" -trimpath -o $dest $package
        return ($LASTEXITCODE -eq 0)
    } finally {
        Pop-Location
        Remove-Item Env:GOOS -ErrorAction SilentlyContinue
        Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
        Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
        Remove-Item Env:GOWORK -ErrorAction SilentlyContinue
    }
}

function Compress-Upx([string]$outFile, [string]$os) {
    if ($os -eq "darwin") {
        Write-Warn "    ↳ UPX 跳过 darwin (Mach-O 压缩产物无法在 macOS 运行)"
        return
    }
    & upx -9 --quiet $outFile 2>$null
    if ($LASTEXITCODE -eq 0) {
        & upx -t $outFile 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Warn "    ↳ UPX 压缩并自检成功"
        } elseif ($RequireUpx) {
            Write-Err "    ↳ UPX 自检失败，终止构建"
            exit 1
        } else {
            Write-Err "    ↳ UPX 自检失败，保留未验证产物"
        }
    } elseif ($RequireUpx) {
        Write-Err "    ↳ UPX 压缩失败，终止构建"
        exit 1
    } else {
        Write-Err "    ↳ UPX 跳过该架构 (暂不支持或失败)"
    }
}

# ------------------------------- 参数解析 -------------------------------

if ($Help) {
    Show-Help
    exit 0
}

$hasCross = $false
$cleanPositionals = @()
foreach ($p in $Positionals) {
    if ($p -eq "cross") { $hasCross = $true }
    elseif ($p -eq "pack") { $Pack = $true }
    elseif ($p -eq "--pack") { $Pack = $true }
    elseif ($p -eq "--all-targets") { $AllTargets = $true }
    elseif ($p -eq "--list") { $List = $true }
    elseif ($p -eq "--require-upx") { $RequireUpx = $true; $Pack = $true }
    elseif ($p -match "^-(c|-component)$") { Write-Err "[!] 参数 $p 请使用 -Component <值>"; exit 1 }
    elseif ($p -match "^-(t|-target)$") { Write-Err "[!] 参数 $p 请使用 -Target <值>"; exit 1 }
    else { $cleanPositionals += $p }
}
if ($hasCross) { $AllTargets = $true }

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Err "[!] 未找到 go，无法编译"
    exit 1
}

if ($List) {
    Show-Supported
    exit 0
}

# 无筛选的 pack 保持旧行为：全平台发行压缩
if ($Pack -and $cleanPositionals.Count -eq 0 -and -not $Component -and -not $Target) {
    $AllTargets = $true
}

$HostTarget = Get-HostTarget
$HostOS = ($HostTarget -split ":")[0]
$HostArch = ($HostTarget -split ":")[1]

$SelectedNames = New-Object System.Collections.Generic.List[string]
function Add-Name([string]$name) {
    if (-not $SelectedNames.Contains($name)) {
        $SelectedNames.Add($name) | Out-Null
    }
}

foreach ($item in $cleanPositionals) {
    if ($item -eq "all") {
        Add-Name "argus"; Add-Name "argus-agent"; Add-Name "argus-server"
        continue
    }
    $mapped = Resolve-ComponentName $item
    if (-not $mapped) {
        Write-Err "[!] 未知组件: $item"
        Show-Supported
        exit 1
    }
    Add-Name $mapped
}

if ($Component) {
    foreach ($requested in ($Component -split ",")) {
        $requested = $requested.Trim()
        if (-not $requested) { continue }
        $mapped = Resolve-ComponentName $requested
        if ($mapped) { $requested = $mapped }
        if ($requested -ne "argus-mcp" -and $requested -ne "yaksha" -and -not $Components.ContainsKey($requested)) {
            Write-Err "[!] 未知组件: $requested"
            Show-Supported
            exit 1
        }
        Add-Name $requested
    }
}

if ($SelectedNames.Count -eq 0) {
    Add-Name "argus"; Add-Name "argus-agent"; Add-Name "argus-server"
}

$SelectedTargets = New-Object System.Collections.Generic.List[string]
if ($Target) {
    foreach ($requested in ($Target -split ",")) {
        $requested = $requested.Trim()
        if (-not $requested) { continue }
        $normalized = ConvertTo-CanonicalTarget $requested
        if (-not (Test-IsSupportedTarget $normalized)) {
            Write-Err "[!] 未知平台: $requested"
            Show-Supported
            exit 1
        }
        if (-not $SelectedTargets.Contains($normalized)) {
            $SelectedTargets.Add($normalized) | Out-Null
        }
    }
} elseif ($AllTargets) {
    foreach ($t in $Targets) { $SelectedTargets.Add($t) | Out-Null }
} elseif ($Component -and $cleanPositionals.Count -eq 0) {
    # 兼容旧用法：只写 -Component 时交叉编译全部平台
    foreach ($t in $Targets) { $SelectedTargets.Add($t) | Out-Null }
} else {
    $SelectedTargets.Add($HostTarget) | Out-Null
}

if ($SelectedTargets.Count -eq 0) {
    Write-Err "[!] 未匹配到任何平台，请检查 -Target 参数"
    exit 1
}

$LocalMode = $true
if ($Target -or $AllTargets) {
    $LocalMode = $false
} elseif ($Component -and $cleanPositionals.Count -eq 0) {
    $LocalMode = $false
}

$OutputDir = $ReleaseDir
if ($LocalMode) { $OutputDir = $BinDir }
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

if (-not $LocalMode -and -not $Component -and -not $Target -and $AllTargets -and $cleanPositionals.Count -eq 0) {
    Write-Host "清理旧的 release 目录..."
    if (Test-Path $ReleaseDir) { Remove-Item -Recurse -Force $ReleaseDir }
    New-Item -ItemType Directory -Force -Path $ReleaseDir | Out-Null
}

Write-Info "======================================="
if ($LocalMode) {
    Write-Info "  Argus 本机构建  ${HostOS}/${HostArch}"
} else {
    Write-Info "  Argus 交叉编译"
}
Write-Info "======================================="

$UseUpx = $false
if ($Pack) {
    if (Get-Command upx -ErrorAction SilentlyContinue) {
        $UseUpx = $true
        Write-Ok "[✔] 检测到 UPX，将开启二进制压缩模式。"
    } else {
        Write-Err "[!] 收到 -Pack 参数，但未安装 upx。跳过压缩。"
        if ($RequireUpx) {
            Write-Err "[!] 当前构建要求 UPX，无法继续。"
            exit 1
        }
    }
}

$NeedCliPackage = (-not $LocalMode) -and $SelectedNames.Contains("argus")
$CliPackageDb = ""
if ($NeedCliPackage) {
    Write-Host ""
    Write-Warn "检查依赖状态..."
    & go mod verify 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Err "[!] 依赖校验失败"
        exit 1
    }
    Write-Ok "[✔] 依赖校验通过"
    $pkgDir = Join-Path $ReleaseDir ".arsenal-package"
    $CliPackageDb = Join-Path $pkgDir "arsenal.db"
    New-Item -ItemType Directory -Force -Path $pkgDir | Out-Null
    if (Test-Path $CliPackageDb) { Remove-Item -Force $CliPackageDb }
    Write-Host ""
    Write-Warn "生成 CLI 离线弹药库..."
    & go run ./scanner/cmd/arsenal-package --config scanner/common/config --output $CliPackageDb
    if ($LASTEXITCODE -ne 0) {
        Write-Err "[!] 生成 CLI 离线弹药库失败"
        exit 1
    }
}

Write-Host ""
Write-Warn "开始编译..."
Write-Info ("组件: " + ($SelectedNames -join ", ") + "，平台: " + (($SelectedTargets | ForEach-Object { $_.Replace(":", "/") }) -join ", "))

$BuiltFiles = New-Object System.Collections.Generic.List[string]

foreach ($target in $SelectedTargets) {
    $os = ($target -split ":")[0]
    $arch = ($target -split ":")[1]
    Write-Host ""
    Write-Info "➤ 目标平台: [${os}/${arch}]"

    foreach ($name in $SelectedNames) {
        $outFile = ""
        $isWindows = ($os -eq "windows")

        switch ($name) {
            "argus-mcp" {
                $outFile = Get-OutputName $name $os $arch $LocalMode
                Write-Host -NoNewline "  编译 [$name] ... "
                if ($UseUpx -and (Test-Path $outFile)) { Remove-Item -Force $outFile }
                if (Invoke-NestedBuild "mcp" $outFile "./cmd/argus-mcp" $os $arch $false) {
                    Write-Ok "成功"
                } else {
                    Write-Err "失败"; exit 1
                }
            }
            "yaksha" {
                if ($os -ne "linux") {
                    Write-Warn "  编译 [yaksha] ... 跳过：yaksha 依赖 cgo libpcre2，仅支持 linux 目标（Windows/Darwin 请以容器方式运行，见 deploy\windows）"
                    continue
                }
                $outFile = Get-OutputName $name $os $arch $LocalMode
                Write-Host -NoNewline "  编译 [$name] ... "
                if ($UseUpx -and (Test-Path $outFile)) { Remove-Item -Force $outFile }
                if (Invoke-NestedBuild "yaksha" $outFile "./cmd/yaksha" $os $arch $true) {
                    Write-Ok "成功"
                } else {
                    Write-Err "失败"; exit 1
                }
            }
            default {
                $record = $Components[$name]
                $tags = $record.Tags
                $path = $record.Path
                # 本机 CLI 使用内嵌规则，交叉编译 CLI 使用 noembed + 离线包
                if ($name -eq "argus" -and $LocalMode) {
                    $tags = ""
                }
                $outFile = Get-OutputName $name $os $arch $LocalMode
                Write-Host -NoNewline "  编译 [$name] ... "
                if ($UseUpx -and (Test-Path $outFile)) { Remove-Item -Force $outFile }
                if (Invoke-GoBuild $path $os $arch $outFile $tags) {
                    Write-Ok "成功"
                } else {
                    Write-Err "失败"; exit 1
                }
            }
        }

        if ($UseUpx) {
            Compress-Upx $outFile $os
        }

        if ($name -eq "argus" -and -not $LocalMode) {
            $stageDir = Join-Path $ReleaseDir (".argus-${os}-${arch}-stage")
            $stageData = Join-Path $stageDir "argus-data\arsenal"
            New-Item -ItemType Directory -Force -Path $stageData | Out-Null
            Copy-Item $outFile (Join-Path $stageDir (Split-Path -Leaf $outFile))
            Copy-Item $CliPackageDb (Join-Path $stageData "arsenal.db")
            $packageFile = Join-Path $ReleaseDir "argus-${os}-${arch}.zip"
            if (Test-Path $packageFile) { Remove-Item -Force $packageFile }
            Compress-Archive -Path (Join-Path $stageDir "*") -DestinationPath $packageFile -CompressionLevel Optimal
            Remove-Item -Recurse -Force $stageDir
            Write-Ok ("    ↳ CLI 离线包: " + $packageFile)
            $BuiltFiles.Add($packageFile) | Out-Null
        }

        $BuiltFiles.Add($outFile) | Out-Null
    }
}

Write-Host ""
Write-Ok "======================================="
Write-Ok ("  编译完成  " + $HostOS + "/" + $HostArch)
Write-Ok "======================================="
foreach ($file in $BuiltFiles) {
    if (Test-Path $file) {
        $size = (Get-Item $file).Length
        Write-Ok ("  {0}  ({1:N0} bytes)" -f $file, $size)
    }
}
