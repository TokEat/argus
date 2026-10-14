# 指纹规则库体检报告（2026-09-15）

数据源：`config/finger.yaml` → `fingerprint_rules` 表，共 **9087** 条规则 / 单一 `web` 分类。
说明：`fingerprint_rules` 对 `(tenant_id, product_name, rule_expr)` 有唯一索引，所以**不存在完全相同的行**；下面的"重复"指**同一检测规则映射到多个产品名**、或**产品名本身近重复/乱码**。

## 总览

| # | 类别 | 数量 | 文件 |
|---|------|------|------|
| A | 跨产品共享同一检测规则 | 34 条 rule-expr，波及 **67 个产品** | `1_duplicate_shared_rules.csv` |
| B | 系统级 typo `（北北京）` | **23 个产品** | `2_typo_beijingbei.csv` |
| C | 地域后缀变体（同基础产品多条） | 11 组（抽样，实际更多） | `3_region_variants.csv` |
| D | Default/Test-Page 类无用指纹 | **31 个产品** | `4_useless_default_test_page.csv` |
| E | 通用技术类低价值指纹 | 19 个产品 | `5_generic_tech.csv` |

## A. 跨产品共享规则（重复产品的根源）

一条规则命中后会对每个挂名产品各报一次，导致**扫一个目标冒出多个"产品"**。

典型：
- `body="webui/js/jquerylib/jquery-1.7.2.min.js"` → 同时是 `H3C-下一代防火墙`、`H3C/安博通/任子行/OEM系列安全产品`、`新华三交换机(华东)`（一条 jquery 规则挂 3 个 H3C 产品）
- `body="//易企邮正式版发布"` → `17mail` 和 `17mail-email`
- `body="/ehr/login/css/login.css"` → `EHR` 和 `EHR系统`
- WebLogic 大段规则 → `BEA-WebLogic-Server` 和 `WebLogic`

→ 见 `1_duplicate_shared_rules.csv`（含完整 rule_expr 与全部挂名产品）。

## B. `（北北京）` typo（23 个）

导入时的字符串事故（应为 `北京`/`华北`）。如 `契约锁(北北京)`、`帆软报表(北北京)`、`O2OA协同办公(北北京)`、`SmartBI(北北京)`、`观远BI(北北京)`。
→ 见 `2_typo_beijingbei.csv`。这些同时与 C 类地域变体重叠。

## C. 地域后缀变体

同一基础产品按 华东/华南/西部/深圳/北京 拆成多条，与 B 类叠加。例：
- `观远BI(北北京)` / `观远BI(深圳)`
- `永洪BI(北北京)` / `永洪BI(西部)`
- `章管家(华南)` / `章管家(西部)`
- `契约锁(北京)` / `契约锁(北北京)`
→ 见 `3_region_variants.csv`。

## D. Default/Test-Page 无用指纹（31 个）

只识别"默认页/测试页"，不代表真实产品，建议禁用：
`Express-Default-Page`、`Tengine-Default-Page`、`Google-Cloud-Run-Default-Page`、`Microsoft-Azure-Default-Page`、`GlassFish-Server-Default-Page`、`WebSphere-Liberty-Default-Page`、`Cakephp-Default-Page`、`SSL-TLS-aware-Test-Page` 等。
→ 见 `4_useless_default_test_page.csv`。

## E. 通用技术低价值指纹（19 个）

框架/语言级识别，误报高、非具体产品：`PHP`、`ASP`、`ThinkPHP`、`jquery`、`.NET`、`Bootstrap`、`WordPress` 等。
→ 见 `5_generic_tech.csv`。

## 后续清理建议（本次未执行）

若要清洗（需先确认 `finger.yaml` 不被上游 Arsenal 同步覆盖）：
1. **A 类**：把跨产品共享 rule 收敛到 canonical 产品名，其余产品删除该 rule（或加别名映射）。
2. **B 类**：`（北北京）` → 合并进基础产品（去地域或改为正确地域）。
3. **C 类**：同一基础产品的地域变体合并为一条。
4. **D/E 类**：规则 `Enabled=false`（软禁用，保留可回溯），不要物理删除。
5. 改动 `finger.yaml` 后需触发规则物化（重建 `fingerprint_rules`）并下发 agent。
