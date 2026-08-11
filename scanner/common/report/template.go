package report

import "html/template"

type pageView struct {
	SchemaVersion string
	RunID         string
	Targets       []string
	SourceFile    string
	StartedAt     string
	FinishedAt    string
	Duration      string
	Status        string
	StatusLabel   string
	Counts        Counts
	Nonce         string
}

type sectionView struct {
	ID          string
	Title       string
	Description string
	Empty       string
	Count       int
}

func sectionFor(category string, counts Counts) sectionView {
	switch category {
	case categoryAssets:
		return sectionView{ID: category, Title: "资产", Description: "本次运行确认的存活主机与域名解析。", Empty: "未记录存活资产。", Count: counts.Assets}
	case categoryServices:
		return sectionView{ID: category, Title: "服务与协议", Description: "开放端口及协议识别结果。", Empty: "未记录开放端口或协议。", Count: counts.Services}
	case categoryWeb:
		return sectionView{ID: category, Title: "Web 服务", Description: "HTTP 状态、页面标题与随 Web 探测返回的技术特征。", Empty: "未记录 Web 服务。", Count: counts.Web}
	case categoryFingerprints:
		return sectionView{ID: category, Title: "指纹", Description: "同一服务与产品已归并；展开可查看被动命中、主动确认和路径推断证据。", Empty: "未记录指纹产品。", Count: counts.Fingerprints}
	case categoryVulnerabilities:
		return sectionView{ID: category, Title: "漏洞证据", Description: "仅展示显式执行的 Nuclei / GoPoc 结果及其证据。", Empty: "未记录漏洞结果；这不代表目标不存在漏洞。", Count: counts.Vulnerabilities}
	default:
		return sectionView{ID: categoryOther, Title: "其他记录", Description: "尚未归入标准类型的结构化扫描输出。", Empty: "没有其他记录。", Count: counts.Other}
	}
}

var pageHeaderTemplate = template.Must(template.New("page-header").Parse(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none'; connect-src 'none'; font-src 'none'; form-action 'none'; frame-src 'none'; img-src data:; object-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-{{.Nonce}}'">
<meta name="referrer" content="no-referrer">
<meta name="generator" content="Argus CLI {{.SchemaVersion}}">
<title>Argus CLI 扫描报告</title>
<style>
:root{color-scheme:light;--brand:#030507;--brand-fg:#f4f7fa;--accent:#0284c7;--accent-soft:#e0f2fe;--page:#f8fafc;--panel:#fff;--text:#1e293b;--muted:#64748b;--line:#e2e8f0;--evidence:#0f172a;--evidence-2:#1e293b;--critical:#7f1d1d;--high:#b91c1c;--medium:#c2410c;--low:#0369a1;--info:#047857;--unknown:#475569}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--page);color:var(--text);font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
a{color:#0369a1;text-decoration:none}a:hover{text-decoration:underline}a:focus-visible,button:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible{outline:3px solid #38bdf8;outline-offset:2px}
.brand-header{background:var(--brand);color:var(--brand-fg);padding:28px clamp(18px,4vw,52px);border-bottom:4px solid var(--accent)}
.brand-row{max-width:1440px;margin:auto;display:flex;align-items:center;gap:18px}.brand-mark{width:58px;height:58px;flex:0 0 auto}.brand-kicker{font-size:12px;letter-spacing:.18em;text-transform:uppercase;color:#94a3b8}.brand-title{margin:2px 0 0;font-size:clamp(26px,4vw,42px);line-height:1.1}.brand-subtitle{margin:8px 0 0;color:#cbd5e1;max-width:780px}
.page{max-width:1440px;margin:0 auto;padding:24px clamp(16px,3vw,40px) 48px}
.notice{display:flex;gap:10px;align-items:flex-start;background:#fff7ed;border:1px solid #fed7aa;color:#9a3412;border-radius:12px;padding:12px 14px;margin-bottom:18px}.notice strong{white-space:nowrap}
.meta-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.meta-card,.stat-card,.section{background:var(--panel);border:1px solid var(--line);border-radius:14px;box-shadow:0 1px 2px rgba(15,23,42,.04)}
.meta-card{padding:14px}.meta-label{color:var(--muted);font-size:12px}.meta-value{margin-top:4px;font-weight:700;overflow-wrap:anywhere}.status-completed{color:#047857}.status-failed{color:#b91c1c}.status-canceled{color:#c2410c}
.targets{display:flex;gap:7px;flex-wrap:wrap;margin:14px 0 0;padding:0;list-style:none}.target{max-width:100%;background:#eef2ff;color:#3730a3;border:1px solid #c7d2fe;border-radius:999px;padding:4px 10px;overflow-wrap:anywhere}.targets-empty{color:var(--muted)}
.stats{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:12px;margin:20px 0}.stat-card{padding:14px 16px}.stat-value{font-size:28px;font-weight:800;line-height:1}.stat-label{margin-top:6px;color:var(--muted);font-size:12px}.stat-detail{margin-top:3px;color:var(--muted);font-size:11px}
.toolbar{position:sticky;top:0;z-index:20;background:rgba(248,250,252,.96);backdrop-filter:blur(10px);border:1px solid var(--line);border-radius:14px;padding:12px;margin:0 0 18px;display:flex;gap:9px;align-items:center;flex-wrap:wrap}.filter-group{display:flex;gap:6px;flex-wrap:wrap}.filter-button,.action-button{appearance:none;border:1px solid #cbd5e1;background:#fff;color:#334155;border-radius:9px;padding:7px 11px;font:inherit;font-weight:650;cursor:pointer}.filter-button[aria-pressed="true"]{background:var(--brand);border-color:var(--brand);color:#fff}.action-button:hover,.filter-button:hover{border-color:#38bdf8}.search{min-width:220px;flex:1;border:1px solid #cbd5e1;border-radius:9px;padding:8px 10px;font:inherit;color:var(--text);background:#fff}.severity-select{border:1px solid #cbd5e1;border-radius:9px;padding:8px;background:#fff;color:var(--text)}.match-count{color:var(--muted);font-size:12px;min-width:72px;text-align:right}
.section{margin:0 0 18px;overflow:hidden}.section-header{padding:18px 20px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;gap:14px;align-items:flex-start}.section-title{margin:0;font-size:20px}.section-description{margin:4px 0 0;color:var(--muted)}.section-count{background:var(--accent-soft);color:#075985;border-radius:999px;padding:3px 10px;font-weight:800}.section-items{padding:4px 20px 20px}
.report-item{border:1px solid var(--line);border-radius:11px;margin-top:12px;background:#fff;overflow:hidden}.record{display:grid;grid-template-columns:minmax(120px,.7fr) minmax(220px,2fr) minmax(80px,.6fr) minmax(160px,1.4fr);gap:12px;padding:14px}.record-type{font-weight:800}.record-main{min-width:0;overflow-wrap:anywhere}.record-main strong{display:block}.record-meta{color:var(--muted);font-size:12px}.record-detail{grid-column:1/-1;margin:0;padding:10px 12px;border-left:3px solid #7dd3fc;background:#f0f9ff;white-space:pre-wrap;overflow-wrap:anywhere}.tag-list{display:flex;gap:5px;flex-wrap:wrap}.tag{display:inline-block;background:#f1f5f9;color:#334155;border:1px solid #cbd5e1;border-radius:999px;padding:2px 8px;font-size:12px}
.vulnerability>summary{list-style:none;cursor:pointer;padding:15px 16px;display:grid;grid-template-columns:auto auto minmax(160px,1fr) minmax(220px,2fr);gap:10px;align-items:center}.vulnerability>summary::-webkit-details-marker{display:none}.vulnerability>summary::before{content:"＋";font-size:18px;color:var(--muted)}.vulnerability[open]>summary::before{content:"−"}.engine{font-weight:800}.severity{display:inline-block;color:#fff;border-radius:6px;padding:2px 8px;font-size:11px;font-weight:850;letter-spacing:.03em}.severity-critical{background:var(--critical)}.severity-high{background:var(--high)}.severity-medium{background:var(--medium)}.severity-low{background:var(--low)}.severity-info{background:var(--info)}.severity-unknown{background:var(--unknown)}.vuln-name{font-weight:800;overflow-wrap:anywhere}.vuln-target{overflow-wrap:anywhere;color:var(--muted)}
.vuln-body{border-top:1px solid var(--line);padding:16px}.vuln-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.vuln-field{border:1px solid var(--line);border-radius:9px;padding:11px}.vuln-field dt{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}.vuln-field dd{margin:5px 0 0;white-space:pre-wrap;overflow-wrap:anywhere}.references{margin:4px 0 0;padding-left:18px}.evidence{margin-top:12px;border:1px solid #334155;border-radius:10px;overflow:hidden;background:var(--evidence);color:#e2e8f0}.evidence>summary{cursor:pointer;padding:10px 12px;background:var(--evidence-2);font-weight:750}.evidence-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1px;background:#334155}.evidence-pane{min-width:0;background:var(--evidence)}.evidence-head{display:flex;align-items:center;justify-content:space-between;padding:8px 10px;color:#94a3b8;font-size:12px}.copy-button{border:1px solid #475569;background:#1e293b;color:#e2e8f0;border-radius:6px;padding:3px 8px;cursor:pointer}.evidence pre,.metadata pre{margin:0;padding:12px;max-height:520px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace}.metadata{margin-top:12px;background:#f8fafc;border:1px solid var(--line);border-radius:9px}.metadata summary{padding:9px 11px;cursor:pointer;font-weight:700}.metadata pre{color:#334155}.empty{padding:26px;text-align:center;color:var(--muted);border:1px dashed #cbd5e1;border-radius:10px;margin-top:12px}.no-results{display:none;margin:20px 0;padding:22px;text-align:center;border:1px dashed #94a3b8;border-radius:12px;color:var(--muted)}
.fingerprint-card{padding:0}.fingerprint-summary{display:grid;grid-template-columns:minmax(150px,.8fr) minmax(220px,1.8fr) auto;gap:14px;align-items:center;padding:15px 16px}.fingerprint-product{font-size:17px;font-weight:850;overflow-wrap:anywhere}.fingerprint-service{min-width:0;overflow-wrap:anywhere}.fingerprint-state{display:inline-block;border-radius:999px;padding:3px 9px;font-size:11px;font-weight:850}.fingerprint-confirmed{background:#dcfce7;color:#166534;border:1px solid #86efac}.fingerprint-suspected{background:#fef3c7;color:#92400e;border:1px solid #fcd34d}.source-list{display:flex;gap:6px;flex-wrap:wrap;margin-top:7px}.source-badge{display:inline-block;border-radius:999px;padding:2px 8px;font-size:11px;font-weight:750;border:1px solid}.source-passive{background:#e0f2fe;color:#075985;border-color:#7dd3fc}.source-active{background:#dcfce7;color:#166534;border-color:#86efac}.source-fallback{background:#fef3c7;color:#92400e;border-color:#fcd34d}.fingerprint-evidence{border-top:1px solid var(--line)}.fingerprint-evidence>summary{cursor:pointer;padding:10px 16px;color:#475569;font-weight:700;background:#f8fafc}.fingerprint-evidence-list{display:grid;gap:8px;padding:12px 16px 16px}.fingerprint-evidence-row{display:grid;grid-template-columns:auto minmax(220px,1.5fr) minmax(120px,.8fr);gap:10px;align-items:start;border:1px solid var(--line);border-radius:9px;padding:10px 12px}.fingerprint-evidence-target{overflow-wrap:anywhere}.fingerprint-evidence-meta{color:var(--muted);font-size:12px}.fingerprint-evidence-detail{grid-column:2/-1;margin:0;padding:8px 10px;background:#fff7ed;border-left:3px solid #f59e0b;white-space:pre-wrap;overflow-wrap:anywhere}
.page-footer{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-top:24px;padding:16px 2px;color:var(--muted);font-size:12px}.page-footer strong{color:var(--text)}
[hidden]{display:none!important}
@media(max-width:1000px){.meta-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.stats{grid-template-columns:repeat(3,minmax(0,1fr))}.record{grid-template-columns:1fr 2fr}.fingerprint-summary{grid-template-columns:minmax(140px,.8fr) minmax(220px,1.5fr)}.fingerprint-summary>div:last-child{grid-column:1/-1}.vulnerability>summary{grid-template-columns:auto auto 1fr}.vuln-target{grid-column:3}.vuln-grid{grid-template-columns:1fr}}
@media(max-width:640px){.brand-header{padding:22px 16px}.brand-mark{width:46px;height:46px}.meta-grid,.stats{grid-template-columns:1fr 1fr}.toolbar{position:static}.record,.fingerprint-summary,.fingerprint-evidence-row{grid-template-columns:1fr}.fingerprint-summary>div:last-child,.fingerprint-evidence-detail{grid-column:1}.vulnerability>summary{grid-template-columns:auto 1fr}.severity{grid-column:2}.vuln-name,.vuln-target{grid-column:1/-1}.evidence-grid{grid-template-columns:1fr}.section-items{padding:4px 12px 14px}.section-header{padding:15px}.match-count{text-align:left}}
@media print{body{background:#fff}.toolbar,.copy-button{display:none!important}.section,.meta-card,.stat-card{box-shadow:none;break-inside:avoid}.report-item{break-inside:avoid}.evidence pre{max-height:none}.brand-header{background:#fff;color:#000;border-bottom:2px solid #000}.brand-kicker,.brand-subtitle{color:#333}.brand-mark rect{fill:#fff}.brand-mark g{fill:#000}}
</style>
</head>
<body>
<header class="brand-header">
  <div class="brand-row">
    <svg class="brand-mark" viewBox="0 0 1024 1024" role="img" aria-label="Argus A 标志">
      <rect x="70" y="70" width="884" height="884" rx="92" fill="#030507" stroke="#F4F7FA" stroke-width="28"/>
      <g transform="translate(132 118) scale(.74)" fill="#F4F7FA">
        <polygon points="196 844 266 844 470 314 400 314"/><polygon points="298 844 420 844 548 486 498 344"/><polygon points="466 154 594 154 860 844 714 844 536 360"/><polygon points="388 594 654 594 696 706 348 706"/>
      </g>
    </svg>
    <div><div class="brand-kicker">ARGUS CLI</div><h1 class="brand-title">授权安全测试扫描报告</h1><p class="brand-subtitle">资产、服务、Web、指纹与经明确授权执行的漏洞验证证据集中在一个离线报告中。</p></div>
  </div>
</header>
<main class="page">
  <aside class="notice" role="note"><strong>敏感扫描产物</strong><span>本报告可能包含目标地址、服务信息与请求/响应证据。请按授权范围妥善保存，页面不会自动请求任何外部资源。</span></aside>
  <section aria-label="扫描元数据">
    <div class="meta-grid">
      <div class="meta-card"><div class="meta-label">运行 ID</div><div class="meta-value">{{.RunID}}</div></div>
      <div class="meta-card"><div class="meta-label">扫描执行状态</div><div class="meta-value status-{{.Status}}">{{.StatusLabel}}</div></div>
      <div class="meta-card"><div class="meta-label">开始 / 完成</div><div class="meta-value">{{.StartedAt}}<br>{{.FinishedAt}}</div></div>
      <div class="meta-card"><div class="meta-label">耗时</div><div class="meta-value">{{.Duration}}</div></div>
    </div>
    <ul class="targets" aria-label="扫描目标">{{range .Targets}}<li class="target">{{.}}</li>{{else}}<li class="targets-empty">未记录目标</li>{{end}}</ul>
  </section>
  <section class="stats" aria-label="结果总览">
    <a class="stat-card" href="#assets"><div class="stat-value">{{.Counts.Assets}}</div><div class="stat-label">资产</div></a>
    <a class="stat-card" href="#services"><div class="stat-value">{{.Counts.Services}}</div><div class="stat-label">服务 / 协议</div></a>
    <a class="stat-card" href="#web"><div class="stat-value">{{.Counts.Web}}</div><div class="stat-label">Web</div></a>
    <a class="stat-card" href="#fingerprints"><div class="stat-value">{{.Counts.Fingerprints}}</div><div class="stat-label">指纹产品</div>{{if .Counts.FingerprintEvents}}<div class="stat-detail">{{.Counts.FingerprintEvents}} 条原始来源记录</div>{{end}}</a>
    <a class="stat-card" href="#vulnerabilities"><div class="stat-value">{{.Counts.Vulnerabilities}}</div><div class="stat-label">漏洞结果</div></a>
    <div class="stat-card"><div class="stat-value">{{.Counts.Records}}</div><div class="stat-label">全部记录</div></div>
  </section>
  <nav class="toolbar" aria-label="报告筛选">
    <div class="filter-group" role="group" aria-label="结果类型">
      <button class="filter-button" type="button" data-category="all" aria-pressed="true">全部</button>
      <button class="filter-button" type="button" data-category="assets" aria-pressed="false">资产</button>
      <button class="filter-button" type="button" data-category="services" aria-pressed="false">服务</button>
      <button class="filter-button" type="button" data-category="web" aria-pressed="false">Web</button>
      <button class="filter-button" type="button" data-category="fingerprints" aria-pressed="false">指纹</button>
      <button class="filter-button" type="button" data-category="vulnerabilities" aria-pressed="false">漏洞</button>
      <button class="filter-button" type="button" data-category="other" aria-pressed="false">其他</button>
    </div>
    <label><span class="meta-label">严重度</span> <select class="severity-select" id="severityFilter"><option value="all">全部</option><option value="CRITICAL">CRITICAL</option><option value="HIGH">HIGH</option><option value="MEDIUM">MEDIUM</option><option value="LOW">LOW</option><option value="INFO">INFO</option><option value="UNKNOWN">UNKNOWN</option></select></label>
    <label class="search"><span class="meta-label">搜索</span><input class="search" id="reportSearch" type="search" autocomplete="off" placeholder="目标、端口、标题、指纹、模板…"></label>
    <button class="action-button" id="expandAll" type="button">展开漏洞</button><button class="action-button" id="collapseAll" type="button">折叠漏洞</button>
    <span class="match-count" id="matchCount" aria-live="polite"></span>
  </nav>
  <div id="noResults" class="no-results" role="status">没有符合当前筛选条件的记录。</div>
`))

var sectionHeaderTemplate = template.Must(template.New("section-header").Parse(`<section class="section report-section" id="{{.ID}}" data-section="{{.ID}}">
  <header class="section-header"><div><h2 class="section-title">{{.Title}}</h2><p class="section-description">{{.Description}}</p></div><span class="section-count">{{.Count}}</span></header><div class="section-items">
`))

var emptySectionTemplate = template.Must(template.New("section-empty").Parse(`<div class="empty">{{.Empty}}</div>`))

var itemHTMLTemplate = template.Must(template.New("item").Parse(`{{if .Vulnerability}}
<details class="report-item vulnerability" data-category="{{.Category}}" data-severity="{{.Vulnerability.Severity}}">
  <summary><span class="engine">{{.Vulnerability.Engine}}</span><span class="severity {{.Vulnerability.SeverityClass}}">{{.Vulnerability.Severity}}</span><span class="vuln-name">{{.Vulnerability.Name}}{{if .Vulnerability.TemplateID}} · {{.Vulnerability.TemplateID}}{{end}}</span><span class="vuln-target">{{if .Vulnerability.Link}}<a href="{{.Vulnerability.Link}}" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer">{{.Vulnerability.Target}}</a>{{else}}{{.Vulnerability.Target}}{{end}}</span></summary>
  <div class="vuln-body"><dl class="vuln-grid">
    {{if .Vulnerability.Description}}<div class="vuln-field"><dt>描述</dt><dd>{{.Vulnerability.Description}}</dd></div>{{end}}
    {{if .Vulnerability.Impact}}<div class="vuln-field"><dt>影响</dt><dd>{{.Vulnerability.Impact}}</dd></div>{{end}}
    {{if .Vulnerability.Remediation}}<div class="vuln-field"><dt>修复建议</dt><dd>{{.Vulnerability.Remediation}}</dd></div>{{end}}
    {{if .Vulnerability.Authors}}<div class="vuln-field"><dt>作者</dt><dd>{{.Vulnerability.Authors}}</dd></div>{{end}}
    {{if .Vulnerability.Tags}}<div class="vuln-field"><dt>标签</dt><dd>{{.Vulnerability.Tags}}</dd></div>{{end}}
    {{if .Vulnerability.Matcher}}<div class="vuln-field"><dt>匹配器</dt><dd>{{.Vulnerability.Matcher}}</dd></div>{{end}}
    {{if .Vulnerability.Additional}}<div class="vuln-field"><dt>结果摘要</dt><dd>{{.Vulnerability.Additional}}</dd></div>{{end}}
    {{if .Vulnerability.Extracted}}<div class="vuln-field"><dt>提取结果</dt><dd>{{range .Vulnerability.Extracted}}<span class="tag">{{.}}</span>{{end}}</dd></div>{{end}}
    {{if .Vulnerability.References}}<div class="vuln-field"><dt>参考资料</dt><dd><ul class="references">{{range .Vulnerability.References}}<li>{{if .URL}}<a href="{{.URL}}" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer">{{.Label}}</a>{{else}}{{.Label}}{{end}}</li>{{end}}</ul></dd></div>{{end}}
  </dl>
  {{range $index, $exchange := .Vulnerability.Exchanges}}<details class="evidence"><summary>{{$exchange.Label}}</summary><div class="evidence-grid">
    <div class="evidence-pane"><div class="evidence-head"><span>请求 / 输入</span><button class="copy-button" type="button" data-copy="{{$.ID}}-request-{{$index}}">复制</button></div><pre id="{{$.ID}}-request-{{$index}}">{{$exchange.Request}}</pre></div>
    <div class="evidence-pane"><div class="evidence-head"><span>响应 / 输出</span><button class="copy-button" type="button" data-copy="{{$.ID}}-response-{{$index}}">复制</button></div><pre id="{{$.ID}}-response-{{$index}}">{{$exchange.Response}}</pre></div>
  </div></details>{{end}}
  {{if .Vulnerability.Metadata}}<details class="metadata"><summary>附加元数据</summary><pre>{{.Vulnerability.Metadata}}</pre></details>{{end}}
  </div>
</details>
{{else if .Fingerprint}}
<article class="report-item fingerprint-card" data-category="{{.Category}}" data-severity="" data-fingerprint-product="{{.Fingerprint.Product}}">
  <div class="fingerprint-summary">
    <div><div class="fingerprint-product">{{.Fingerprint.Product}}</div><div class="source-list">{{range .Fingerprint.Sources}}<span class="source-badge {{.Class}}">{{.Label}}</span>{{end}}</div></div>
    <div class="fingerprint-service">{{if .Fingerprint.Link}}<strong><a href="{{.Fingerprint.Link}}" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer">{{.Fingerprint.Service}}</a></strong>{{else}}<strong>{{.Fingerprint.Service}}</strong>{{end}}<div class="record-meta">{{.Fingerprint.EvidenceText}}</div></div>
    <div><span class="fingerprint-state {{.Fingerprint.StateClass}}">{{.Fingerprint.StateLabel}}</span></div>
  </div>
  <details class="fingerprint-evidence"><summary>查看来源证据</summary><div class="fingerprint-evidence-list">
    {{range .Fingerprint.Evidence}}<div class="fingerprint-evidence-row"><span class="source-badge {{.SourceClass}}">{{.SourceLabel}}</span><div class="fingerprint-evidence-target">{{if .Link}}<a href="{{.Link}}" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer">{{.Endpoint}}</a>{{else}}{{.Endpoint}}{{end}}</div><div class="fingerprint-evidence-meta">{{if .Status}}HTTP {{.Status}}{{end}}{{if .Title}}<br>{{.Title}}{{end}}</div>{{if .Details}}<pre class="fingerprint-evidence-detail">{{.Details}}</pre>{{end}}</div>{{end}}
  </div></details>
</article>
{{else}}
<article class="report-item record" data-category="{{.Category}}" data-severity="">
  <div><span class="record-type">{{.TypeLabel}}</span><div class="record-meta">{{.Type}}</div></div>
  <div class="record-main">{{if .Link}}<strong><a href="{{.Link}}" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer">{{.Endpoint}}</a></strong>{{else}}<strong>{{.Endpoint}}</strong>{{end}}{{if .IP}}<span class="record-meta">IP {{.IP}}</span>{{end}}</div>
  <div><strong>{{.Status}}</strong>{{if .Port}}<div class="record-meta">端口 {{.Port}}</div>{{end}}{{if .Protocol}}<div class="record-meta">{{.Protocol}}</div>{{end}}</div>
  <div><strong>{{.Title}}</strong>{{if .Location}}<div class="record-meta">{{.Location}}</div>{{end}}{{if .Fingerprints}}<div class="tag-list">{{range .Fingerprints}}<span class="tag">{{.}}</span>{{end}}</div>{{end}}</div>
  {{if .Details}}<pre class="record-detail">{{.Details}}</pre>{{end}}
</article>
{{end}}`))

var pageFooterTemplate = template.Must(template.New("page-footer").Parse(`
  <footer class="page-footer"><span><strong>Argus CLI</strong> · 自包含离线报告 · {{.SchemaVersion}}</span><span>扫描执行状态不包含 stdout/result 终结；进程终态以退出码和 run_summary 为准</span><span>原始结果保留于：{{.SourceFile}}</span></footer>
</main>
<script nonce="{{.Nonce}}">
(function(){
  'use strict';
  var category='all';
  var items=Array.prototype.slice.call(document.querySelectorAll('.report-item'));
  var sections=Array.prototype.slice.call(document.querySelectorAll('.report-section'));
  var buttons=Array.prototype.slice.call(document.querySelectorAll('.filter-button'));
  var severity=document.getElementById('severityFilter');
  var search=document.getElementById('reportSearch');
  var matchCount=document.getElementById('matchCount');
  var noResults=document.getElementById('noResults');
  function apply(){
    var query=search.value.trim().toLocaleLowerCase();
    var severityValue=severity.value;
    var visible=0;
    items.forEach(function(item){
      var categoryMatch=category==='all'||item.dataset.category===category;
      var itemSeverity=item.dataset.severity||'';
      var severityMatch=severityValue==='all'||itemSeverity===severityValue;
      var textMatch=query===''||item.textContent.toLocaleLowerCase().indexOf(query)!==-1;
      item.hidden=!(categoryMatch&&severityMatch&&textMatch);
      if(!item.hidden){visible++;}
    });
    sections.forEach(function(section){
      var hasVisible=Array.prototype.some.call(section.querySelectorAll('.report-item'),function(item){return !item.hidden;});
      var hasRecords=section.querySelectorAll('.report-item').length>0;
      section.hidden=(category!=='all'&&section.dataset.section!==category)||(hasRecords&&!hasVisible);
    });
    matchCount.textContent=visible+' 条记录';
    noResults.style.display=visible===0?'block':'none';
  }
  buttons.forEach(function(button){button.addEventListener('click',function(){category=button.dataset.category;buttons.forEach(function(item){item.setAttribute('aria-pressed',String(item===button));});apply();});});
  severity.addEventListener('change',apply);search.addEventListener('input',apply);
  document.getElementById('expandAll').addEventListener('click',function(){items.forEach(function(item){if(!item.hidden&&item.tagName==='DETAILS'){item.open=true;}});});
  document.getElementById('collapseAll').addEventListener('click',function(){items.forEach(function(item){if(item.tagName==='DETAILS'){item.open=false;}});});
  document.addEventListener('click',function(event){
    var button=event.target.closest('[data-copy]');if(!button){return;}
    var target=document.getElementById(button.dataset.copy);if(!target){return;}
    var value=target.textContent;
    function done(){var old=button.textContent;button.textContent='已复制';setTimeout(function(){button.textContent=old;},1200);}
    if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(value).then(done);return;}
    var area=document.createElement('textarea');area.value=value;area.setAttribute('readonly','');area.style.position='fixed';area.style.opacity='0';document.body.appendChild(area);area.select();try{document.execCommand('copy');done();}finally{document.body.removeChild(area);}
  });
  apply();
})();
</script>
</body>
</html>
`))
