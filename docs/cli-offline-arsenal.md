# CLI 离线弹药库

Argus CLI 的正式离线发行包同时包含可执行文件与版本化 `arsenal.db`：

```text
argus.exe
argus-data/
  arsenal/
    arsenal.db
```

CLI 不会联网同步或上传规则。启动扫描时会校验 SQLite 文件类型、运行时表结构、规则完整性、POC 执行分类、风险等级和所有物化路径，再把规则原子物化到 `argus-data/arsenal/config/`。后续启动使用数据库文件 SHA-256 判断是否变化，规则内容版本则使用与记录顺序、时间戳无关的语义 SHA-256。

`ARGUS_HOME` 仍可覆盖 `argus-data` 根目录。首次使用自定义目录时，CLI 会从可执行文件旁的发行包复制一份已校验的 `arsenal.db`；源码开发构建没有外部数据库时继续使用编译时内嵌规则。

## 本地替换或导入

1. 确认没有 Argus CLI 进程正在使用该目录。
2. 将 Server 导出的 Agent 运行时数据库（`/api/v1/arsenals/db`）保存为 `argus-data/arsenal/arsenal.db`。不要使用安装迁移用途的 `arsenal_seed.db`，两者 schema 不同。
3. 再次启动 CLI。校验成功后，新版本自动物化；校验失败则停止启动，不会把损坏内容混入当前规则目录。

每次成功激活的数据库最多保留三份只读恢复快照：

```text
argus-data/arsenal/packages/<file-sha256>/arsenal.db
```

需要回滚时，在 CLI 停止状态下把所需快照复制回固定 `arsenal.db` 路径。普通扫描参数没有变化，也没有新增联网、workspace 或数据库参数。

## 构建发行包

`build.sh` 在构建 `argus` 组件时，从仓库审查基线 `scanner/common/config` 生成与 Server/Agent 同源的运行时数据库，并用 `noembed` 构建正式 CLI，避免在可执行文件和数据库中重复携带大批 POC。输出压缩包包含可执行文件和固定目录：

```bash
./build.sh --component argus --target windows/amd64
```

输出包括原二进制和 `release/argus-windows-amd64.tar.gz`。运行时数据库是生成物，不提交到 Git。
