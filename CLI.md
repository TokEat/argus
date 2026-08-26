# Argus CLI 参数说明

本文根据当前代码整理 Standalone CLI 的命令行行为。
入口：`scanner/cmd/cli/main.go`，参数定义：`scanner/common/flag.go`，扫描默认：`scanner/internal/localplanner/planner.go`。
当前版本字符串：`Argus CLI v2.0.1`。

更细的输出契约见 [docs/cli-output.md](docs/cli-output.md)，离线规则库见 [docs/cli-offline-arsenal.md](docs/cli-offline-arsenal.md)。

---

## 1. 怎么调用

| 用法 | 走哪条路 |
| --- | --- |
| `argus --version`（必须单独这一个参数） | 立刻打印版本，退出 0 |
| `argus -h` / `--help` | 打印扫描参数帮助 |
| `argus -a <目标> [扫描参数…]` | 本地扫描 |
| `argus -tr <目标>` | 只做内网路径探测，不跑端口 / 指纹 / POC |

没有 `-a` / `--target`，且不是 `-tr`，解析后报「无目标输入」，退出 2。

解析器 `CaseSensitive = true`。版本只有 `argus --version`。

---

## 2. 默认扫描实际做什么

`argus -a 10.0.0.1` 默认会：

- 常用协议端口集 + 主机发现（同网段 ARP，其余 ICMP，ICMP 全空再 TCP 探活）+ TCP 端口/协议/Web/指纹
- 默认对同网段高价值 UDP 服务做识别（可用 `-nudp` 关闭）
- **跑 Nuclei**（按 fingerprint → workflow 映射；Interactsh 默认关）
- **跑全部 GoPoc**，含服务口令爆破

Server / Agent 任务默认仍然关 POC，不受这里影响。

关掉能力用：

| 开关 | 效果 |
| --- | --- |
| `-nopoc` | 只关 Nuclei，GoPoc 继续 |
| `-nogpoc` | 关全部 GoPoc（漏洞类 + 爆破 + 探测） |
| `-nobr` | 只关服务口令爆破；MS17-010、Shiro 密钥等仍跑 |
| `-nopoc -nogpoc` | 只做资产发现（Nuclei 与 GoPoc 全关） |

> 注意：`datas` 历史增量跳过（已见 IP 自动跳过）只由显式 `-ss`/`--skip-seen` 开启，`-nopoc -nogpoc` 不会隐式开启它。

> 安全默认：Standalone CLI 默认执行 Nuclei POC 与 GoPoc（含服务口令爆破），请在授权目标上使用；`-nopoc`/`-nogpoc`/`-nobr` 可按需关闭。

冲突（退出 2）：

- `-nopoc` 与 `-poc`
- `-pwda`/`-usea` 与 `-nobr` / `-nogpoc` / `-up` / `-upf`

把上次的 `result.txt`（或整个结果目录）交给 `-a`，会读出 `[Alive]` / `[Port]` / `[Protocol]` 并复用：

- 只有存活主机：自动 `-Pn`，对这些 IP 做端口扫描
- 已有开放端口：不再探活、不再扫这些端口，直接协议识别 / Web / POC / 爆破

```bash
# 第一轮：大段探活+端口（按你的开关）
go run ./scanner/cmd/cli -a 10.0.0.0/16 -nopoc -nogpoc

# 第二轮：在上次存活主机上补端口，或在上次端口上做 POC/爆破
go run ./scanner/cmd/cli -a datas/<上次目录>
go run ./scanner/cmd/cli -a datas/<上次目录>/result.txt
```

`-ss` 是另一回事：打开后会跳过 `datas` 里已经出现过的 IP，默认关。和「读上次结果继续往下做」不是同一开关。

---

## 3. 扫描参数

### 3.1 目标与线程

| 参数 | 短 | 默认 | 说明 |
| --- | --- | --- | --- |
| `--target` | `-a` | 空，必填 | 扫描目标。多个用逗号。若该字符串是已存在文件路径，则按文件读入 |
| `--force` | `-f` | false | 与 `-ss` 一起用时，不跳过 datas 历史 |
| `--skip-seen` | `-ss` | false | 跳过 `datas` 里已经出现过的 IP。默认关闭 |
| `--tcp-scan-threads` | `-t` | Linux 4000，其它 1000 | 只调 TCP 端口扫描线程。超过 `ulimit -n` 时下调 |

`-a` 支持：IPv4、CIDR、范围、`IP:Port`、域名、URL、文件。不支持 IPv6。
`-t` 必须是正整数。

### 3.2 端口扫描

| 参数 | 短 | 默认 | 说明 |
| --- | --- | --- | --- |
| `--port` | `-p` | 常用协议端口集 | TCP 端口列表。UDP 不走这张表 |
| `--scan-type` | `-st` | `tcp` | `tcp` 或 `syn` |
| `--syn-scan-threads` | `-sst` | 10000 | SYN 发包速率（包/秒；仅 Linux raw socket） |
| `--ports-max-count` | `-pmc` | 300 | 单 IP 开放端口超限则丢弃 |
| `--port-scan-timeout` | `-pst` | 6 | TCP 超时，秒 |

### 3.3 主机发现

默认：**同网段 ARP，其余 ICMP**。ARP/ICMP 没回的主机再补一轮 TCP 探活 `80,443,3389,445,22`（不是 `-p` 全端口）。主机防火墙丢 ICMP 时，仍可能被 445/3389/80 打到。有命中才缩小目标；都没打到则仍扫原始 IP，避免空跑。

| 参数 | 短 | 默认 | 说明 |
| --- | --- | --- | --- |
| `-Pn` | `-Pn` | false | 不做存活探测，全部目标直接端口扫描 |
| `--no-icmp-ping` | `-nip` | false | 不用 ICMP，改用 TCP 探活；同网段仍先 ARP |
| `--udp-ping` | `-PU` | false | UDP 探活：向常关口 `40125` 发包，收到 ICMP port unreachable（或 UDP 应答）视为存活 |

| 命令 | 实际探活 |
| --- | --- |
| 默认 | 同网段 ARP，其余 ICMP；没回的再 TCP |
| `-nip` | 同网段 ARP，其余 TCP |
| `-PU` | 默认探活之后，仍没回的再 UDP |
| `-nip -PU` | 同网段 ARP，其余 TCP，没回的再 UDP |
| `-Pn` | 不探活，全扫 |

`-Pn` 优先。读上次 `result.txt` 复用存活/端口时会自动 `-Pn`。ARP 打不开（无网卡、无权限）时，同网段改走 ICMP（或 `-nip` 时走 TCP）。

### 3.4 内网路径 / 蓝图

和扫描流水线分开，是单独命令。后面直接跟目标：单 IP、网段、IP 列表文件，或上次的 `result.txt` / 结果目录。不探活、不扫端口、不跑指纹和 POC。

| 参数 | 短 | 默认 | 说明 |
| --- | --- | --- | --- |
| `--trace` | `-tr` | （空） | 单独路径探测。后跟 IP / 网段 / 结果文件 |

```bash
go run ./scanner/cmd/cli -tr 192.0.2.9
go run ./scanner/cmd/cli -tr res.txt
go run ./scanner/cmd/cli -tr datas/<上次目录>
```

`-tr` 自己带目标，不要写成 `-a ... -tr`。读 `result.txt` 时用里面的存活主机和开放端口 IP。每个 `/24` 最多抽 2 台，总共最多 32 个代表。大网段就地抽样，不会把 `/8` 展开成上千万地址。自己发 UDP/ICMP（递增 TTL）并听 Time Exceeded，不调用系统 `traceroute`/`tracert`。听不到 ICMP 就跳过路径，不伪造跳数。中间跳丢包或晚到时，每跳会连探 3 次，并用内层端口/序号对上 TTL，避免把上一跳的晚到包记到下一跳；一直不回的路由器记 `*`，后面有回应仍继续走到终点。

```text
[Path] 10.0.2.20 hops=2 10.0.0.1 -> 10.0.2.1 -> 10.0.2.20
[Topo] 10.0.0.1 -> 10.0.2.1 -> 10.0.2.0/24
```

`[Path]` 是一台代表主机的路径。`[Topo]` 把终点收成 `/24`，相同路径只留一行。读 `result.txt` 复用时不会把这两类行当成新目标。

### 3.5 协议 / Web / 子域 / 代理 / 输出

`-tc`、`-nto`、`-nudp`、`-sd`、`-nsb`、`-ns`、`-sbt`、`-ld`、`-ac`、`-nhb`、`-ndp`、`-nsi`、`-wt`、`-wto`、`-nd`、`-x`/`--proxy`、`-pt`、`-ptu`、`-o`、`-ot`、`-ho`。`-PU` 见主机发现。

`-ld`/`--local-domain` 默认关闭：域名解析到私网/回环地址时默认不进入存活探测与端口扫描，开启后才纳入扫描。

`-nsi`/`--no-resolved-ip-scan` 默认关闭：开启后非 CDN 域名的解析 IP 完全不做存活探测和端口扫描，仅按任务端口设置对域名本身做 `域名:端口` 形式的 http(s) 盲探。

`-ndp`/`--no-domain-probe` 默认关闭：域名目标的解析 IP 上发现开放 Web 端口时，Web 探测以 `域名:端口` 形式发起并产出资产（例如导入 `abc.com` 得到 `[WEB] http://abc.com:8080/`），不会再用解析 IP 重复探测。加 `-ndp` 回退为旧的 `IP:端口` 探测形式。

`-ac`/`--allow-cdn` 默认关闭：CDN 判定只保留高置信度规则（CNAME 命中已知 CDN/WAF 关键字或精确 IP），「多 IP+CNAME」「含 IPv6」等易误伤自建负载均衡与双栈站点的启发式已移除。开启后不对 CDN 域名的解析 IP 做端口扫描，而是按任务端口设置（与 IP 目标端口扫描同源）对 CDN 域名本身做 `域名:端口` 形式的 http(s) 补偿探测；被判定为 CDN 的域名与其探测结果都会带疑似 CDN 标记，在结果资产列表中可筛选。

`-p` 只做 TCP。UDP 在端口扫描阶段另走第一波单播探针：`53`、`88`、`123`、`137`、`161`、`500`、`1900`、`5060`、`5353`。只打已确认存活的主机（ARP/ICMP/TCP 探活命中，或已有开放 TCP 端口），超时当关闭。有应答才记开放 UDP 口。文本不再单独打 `[Protocol]`，服务名写在端口行上：

```text
[Port] [tcp] 10.0.0.8:445 smb
[Port] [udp] 10.0.0.8:53 dns
[Port] [web] 10.0.0.8:80 http
```

`[web]` 只表示这是 HTTP/HTTPS 口。后面仍会做 Web 探测和指纹识别，文本按同源（协议+主机+端口）合成一条 `[WEB]`，根路径 302 和落地页不会拆成两块：

```text
[WEB] https://10.0.0.8/
     [Finger] nginx,php
     [Certificates] CN=10.0.0.8 SAN=intranet.local issuer=ExampleCA
     [Code] 302
     [Size] 2862
     [Redirect] https://10.0.0.8/login
     [Title] Home
[POC] [cve-2021-41773] [high] http://10.0.0.8/cgi-bin/
```

Nuclei / GoPoc 命中都会打 `[POC]`，包括 `gitlab-detect` 这类 info 探测。模板语法/运行时告警进审计日志，默认终端只留引擎启动、进度和命中。

HTTPS 口（443/8443 等）即使协议识别写成 `http`，仍会再打一轮 `https://` 才能抓到证书。没有 TLS 的纯 HTTP 口不会出现 `[Certificates]`。SAN-only 证书会用 SAN 顶上 CN。

Workflow / POC 仍只读正式指纹阶段写入的 ResultMap，Web 探测里的即时指纹只用于展示。

`-nudp` 关掉 UDP。

`-ot` 仅 `text` 或 `json`。结果目录在当前工作目录 `datas/<任务_时间>/`。

### 3.5 漏洞 / 爆破

| 参数 | 短 | 默认 | 说明 |
| --- | --- | --- | --- |
| `--nopoc` | `-nopoc` | false | 关 Nuclei |
| `--show-poc-map` | `-spm` | false | 打印指纹到 Nuclei POC 的映射和加载的模板列表 |
| `--no-gopoc` | `-nogpoc` | false | 关全部 GoPoc |
| `--no-brute` | `-nobr` | false | 关服务口令爆破 |
| `--poc-name` | `-poc` | 空 | 模糊匹配 Nuclei 模板名 |
| `--no-interactsh` | `-ni` | true | 排除反连模板 |
| `--golang-poc-threads` | `-gpt` | 50 | GoPoc 线程 |
| `--username-password` | `-up` | 空 | **替换**内置字典，格式 `admin : password` |
| `--username-password-file` | `-upf` | 空 | **替换**内置，一行一对 |
| `--password-append` | `-pwda` | 空 | **追加**密码。已存在文件则一行一个，否则空白分词 |
| `--user-append` | `-usea` | 空 | **追加**用户。规则同 `-pwda` |

`-pwda` / `-usea` 展开：保留内置 `user : pass` 对，再做追加用户 × 全部密码、追加密码 × 全部用户，去重后交给各协议插件。若值碰巧是已存在文件名，会按文件读。

审计：`-ad` / `--audit`、`-alf`。
WAF 绕过头默认开，`-nwb` 关掉；`-nws` 关多指纹跳过 POC。

规则文件：`-nt`、`-wy`、`-fy`、`-dy`、`-swl`。

---

## 4. 目录

环境变量 `ARGUS_HOME` 覆盖离线规则根目录。扫描证据写 `./datas/`。

---

## 5. 退出码

| 码 | 含义 |
| --- | --- |
| 0 | 完成，或 help / version |
| 1 | 扫描、输出或本地历史失败 |
| 2 | 参数 / 目标 / 输出类型错误 |
| 130 | Ctrl+C |

---

## 6. 常用例子

```bash
argus -a 10.0.0.0/24
argus -a targets.txt -p 80,443,22 -t 800
argus -a 10.0.0.1 -nopoc
argus -a 10.0.0.1 -nogpoc
argus -a 10.0.0.1 -nopoc -nogpoc
argus -a 10.0.0.1 -pwda "123456 admin@123"
argus -a 10.0.0.1 -pwda ./extra-pass.txt -usea ./extra-user.txt
argus -a 10.0.0.1 -ad
```
