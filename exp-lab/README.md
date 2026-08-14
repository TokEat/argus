# Argus EXP Lab

本目录只用于本机授权的 EXP 开发验收，不属于生产 Compose。靶机、Yaksha 与 Canary 通过内部网络 `argus-exp-lab` 通信；Canary 不发布宿主端口。

```bash
make exp-lab-up
make exp-lab-smoke
make exp-lab-down
```

开发 Server 仅在同时使用 `--dev` 和 `ARGUS_EXP_LAB_SEED=true` 时幂等导入 `lab-shiro-cve-2016-4437-rce` 与 `lab-telnet-unauth-rce`。相同源码哈希的 Published Revision 会直接复用；源码变化才创建新 Draft，并在 Inspect、Contract Validate 和离线 Fixture 全部通过后发布为 Active。

实验脚本只执行无持久化命令：Shiro 使用 Docker 内网 TTL Canary 回证，Telnet 只执行 `id` 与随机标记；不写 WebShell，不建立反弹 Shell。
