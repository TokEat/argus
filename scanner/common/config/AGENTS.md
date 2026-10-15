# 弹药库（Arsenal）治理规范

## 1. 双副本同步
- `config/` 与 `scanner/common/config/` 必须保持 100% 同步，任何变更必须同时修改两处，禁止单边修改。

## 2. 目录探测 (`dir.yaml`)
- **禁止项**：严禁收录任何通过根路径访问会自动 302 跳转的落地页（如各类登录页、后台页）。此类页面由探活跳转（Natural Path）自然跟随并由被动指纹匹配。
- **允许项**：仅收录根路径不跳转、静默部署且默认不暴露的非标准深度端点（如 Nacos、TongWeb、Druid、Actuator、Docker API、Jolokia 等）。
- **归一化**：禁止大小写重复；单产品仅保留 1~2 个高特异性路径。

## 3. 工作流编排 (`workflow.yaml`)
- **命名铁律**：严禁使用中文命名 PoC 物理文件。
- **一致性要求**：`workflow.yaml 条目名` == `pocs/ 磁盘文件名(无 .yaml)` == `PoC 内部 id 字段`，三者必须完全一致。
- **闭环要求**：新增指纹必须补齐对应 workflow 映射；新增 PoC 必须在 workflow 中声明；禁止存在无效引用（断链）。

## 4. PoC 模板 (`pocs/`)
- **匹配条件**：包含多个 matcher（如状态码 + 响应体）时，**必须显式声明 `matchers-condition: and`**，严禁依赖默认的 `or`（避免任意 200 状态码误报）。
- **ID 唯一性**：`id` 必须全库唯一且采用 kebab-case；严禁使用 `template-id` 占位符；复制已有模板必须修改 `id`，严禁同名覆盖。
- **安全边界**：仅允许无害探测（版本信息、固定报错、特征字段、数学回显等），严禁包含破坏性载荷。

## 5. 协议字典 (`dict/`)
- **去重**：入库前必须全局去重，字典内重复率必须为 0%。
- **规模与隔离**：禁止跨协议整库盲目复用；厚重协议（RDP、SMB、PostgreSQL、SSH）必须控制字典规模，防止触发目标风控封禁。

## 6. 提交前自检清单
1. `dir.yaml`：无常规 302 落地页混入。
2. `workflow.yaml`：引用的 PoC 在 `pocs/` 下均存在同名英文文件。
3. `pocs/`：多 matcher 均显式配置 `condition: and`；全局无重复 `id` 与 `template-id`。
4. `dict/`：所有 `.txt` 重复行数为 0。
5. 双副本比对：`diff -r config/ scanner/common/config/` 无差异。
