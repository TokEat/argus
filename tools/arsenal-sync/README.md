# arsenal-sync

`arsenal-sync` 是 Argus 的离线弹药库同步工具，用于把 Server 导出的 `arsenal_seed.db` 还原成 CLI / Scanner 使用的本地规则目录形态。

它解决的是这一段链路：

```text
Web/DB 弹药库治理
  -> 导出 arsenal_seed.db
  -> arsenal-sync diff / export / apply
  -> scanner/common/config
  -> Git diff review / 提交
```

## 使用场景

- 前端弹药库治理后，把已发布规则同步回 `scanner/common/config`。
- 对比当前本地规则目录和 Server DB 中 Approved 规则的差异。
- 导出一份临时 CLI 形态规则目录做检查。
- 在提交规则文件前生成可 review 的 Git diff。

## 命令总览

```bash
go run ./tools/arsenal-sync diff --seed-db <path> --config scanner/common/config
go run ./tools/arsenal-sync export --seed-db <path> --out <staging-dir>
go run ./tools/arsenal-sync apply --seed-db <path> --config scanner/common/config --yes
```

## 参数说明

### 通用参数

| 参数 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `--seed-db` | 是 | 无 | `arsenal_seed.db` 路径。通常来自 `/api/v1/arsenals/seed-db` 或 `deploy/arsenal_seed.db` |

### `diff`

只对比，不写入文件。

```bash
go run ./tools/arsenal-sync diff \
  --seed-db /path/to/arsenal_seed.db \
  --config scanner/common/config
```

| 参数 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `--config` | 否 | `scanner/common/config` | 当前本地 Scanner 规则目录 |

输出示例：

```text
A pocs/TongWeb-Rce.yaml
M finger.yaml
M workflow.yaml
D pocs/old-rule.yaml
```

含义：

- `A`：seed DB 中有，本地目录没有。
- `M`：两边都存在，但内容不同。
- `D`：本地目录有，seed DB 的受管范围中没有。

### `export`

导出到一个新的 staging 目录，不覆盖当前规则目录。

```bash
go run ./tools/arsenal-sync export \
  --seed-db /path/to/arsenal_seed.db \
  --out /private/tmp/argus-arsenal-export
```

| 参数 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `--out` | 是 | 无 | 导出目标目录。该目录必须不存在，工具会自动创建 |

适合先检查导出结果：

```bash
find /private/tmp/argus-arsenal-export -maxdepth 2 -type f | head
```

### `apply`

把 seed DB 中的 Approved 规则同步到本地 `scanner/common/config`。

```bash
go run ./tools/arsenal-sync apply \
  --seed-db /path/to/arsenal_seed.db \
  --config scanner/common/config \
  --backup-root data/arsenal/config-backups \
  --yes
```

| 参数 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `--config` | 否 | `scanner/common/config` | 要覆盖的 Scanner 规则目录 |
| `--backup-root` | 否 | `data/arsenal/config-backups` | 覆盖前备份目录 |
| `--yes` | 是 | `false` | 显式确认覆盖受管文件；不传会拒绝执行 |

`apply` 行为：

- 先生成临时 staging 目录。
- 先计算 diff。
- diff 为空时不创建备份、不重写文件。
- diff 非空时备份整个 `--config` 到 `--backup-root/<timestamp>/config`。
- 只覆盖受管文件。

## 受管范围

`arsenal-sync` 只处理会影响 Scanner 规则加载的文件：

| seed DB type | 输出位置 |
|--------------|----------|
| `finger` | `finger.yaml` |
| `workflow` | `workflow.yaml` |
| `dir` | `dir.yaml` |
| `poc` | `pocs/<file_name>` |
| `poc_asset` | `pocs/<relative_path>` |
| `config_asset` | 仅支持 `dict/*.txt` 和 `subdomains.txt` |

不处理：

- `api-config.yaml`
- `socket.yaml`
- Draft 规则
- EXP
- 未在受管范围内的本地文件

## 推荐同步流程

1. 从 Server 下载最新 seed DB。

```bash
curl -L \
  -H "Authorization: Bearer <JWT>" \
  http://127.0.0.1:8085/api/v1/arsenals/seed-db \
  -o /private/tmp/arsenal_seed.db
```

2. 先查看差异。

```bash
go run ./tools/arsenal-sync diff \
  --seed-db /private/tmp/arsenal_seed.db \
  --config scanner/common/config
```

3. 确认差异合理后同步。

```bash
go run ./tools/arsenal-sync apply \
  --seed-db /private/tmp/arsenal_seed.db \
  --config scanner/common/config \
  --yes
```

4. 做基础验证。

```bash
git diff --check -- scanner/common/config
go test ./tools/arsenal-sync ./scanner/internal/arsenal
```

5. 检查 Git diff 后提交。

```bash
git diff --stat -- scanner/common/config
git status --short --untracked-files=all
```

如果新增 POC 被 `.gitignore` 忽略，需要精确强制暂存：

```bash
git add -f scanner/common/config/pocs/<new-poc>.yaml
```

## 注意事项

- `apply` 只导出 `state=Approved` 的规则，Draft 不会进入本地规则基线。
- `--backup-root` 不能等于或位于 `--config` 内部，工具会拒绝这种用法，避免递归备份污染规则目录。
- `config_asset` 只允许 `dict/*.txt` 和 `subdomains.txt`，其他路径会被拒绝。
- 路径中包含绝对路径、`../`、反斜杠逃逸或 symlink 的情况会被拒绝。
- 如果 seed DB 不包含 `subdomains.txt` 或 `dict/*.txt`，`apply` 会保留本地已有文件并输出 warning。

## 回滚

`apply` 有差异时会创建备份：

```text
data/arsenal/config-backups/<timestamp>/config
```

需要回滚时可以从备份恢复：

```bash
cp -R data/arsenal/config-backups/<timestamp>/config/* scanner/common/config/
```

如果已经提交，也可以使用 Git 回滚对应提交：

```bash
git revert <commit>
```
