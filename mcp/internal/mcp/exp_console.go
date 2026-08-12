package mcp

const (
	expConsoleURI      = "ui://argus/exp-console"
	expConsoleMIMEType = "text/html;profile=mcp-app"
)

var expConsoleMeta = map[string]interface{}{
	"ui": map[string]interface{}{
		"csp": map[string]interface{}{
			"connectDomains":  []string{},
			"resourceDomains": []string{},
			"frameDomains":    []string{},
			"baseUriDomains":  []string{},
		},
		"prefersBorder": true,
	},
}

// expConsoleHTML is deliberately self-contained. It has no network, file, or
// clipboard capability; all runtime actions are sent back through tools/call.
const expConsoleHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Yaksha EXP Console</title>
  <style>
    :root { color-scheme: light dark; font-family: var(--font-sans, ui-sans-serif, system-ui, sans-serif); }
    * { box-sizing: border-box; }
    body { margin: 0; color: var(--color-text-primary, #172033); background: var(--color-background-primary, #f6f8fb); }
    main { display: grid; gap: 12px; padding: 14px; }
    header { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    h1 { margin: 0; font-size: 18px; }
    .muted { color: var(--color-text-secondary, #667085); font-size: 12px; }
    .panel { border: 1px solid var(--color-border-primary, #d8dee9); border-radius: 10px; background: var(--color-background-secondary, #fff); padding: 12px; }
    .grid { display: grid; grid-template-columns: minmax(0, 1.4fr) minmax(260px, .6fr); gap: 12px; }
    label { display: grid; gap: 5px; font-size: 12px; font-weight: 600; }
    textarea, select, input { width: 100%; border: 1px solid var(--color-border-primary, #cfd7e3); border-radius: 7px; color: inherit; background: var(--color-background-primary, #fff); padding: 8px; font: 12px ui-monospace, SFMono-Regular, Menlo, monospace; }
    textarea { resize: vertical; min-height: 92px; }
    #source { min-height: 330px; }
    .actions { display: flex; flex-wrap: wrap; align-items: end; gap: 8px; margin-top: 10px; }
    .actions label { min-width: 140px; }
    button { border: 0; border-radius: 7px; padding: 9px 14px; color: white; background: #3157d5; cursor: pointer; font-weight: 650; }
    button:disabled { opacity: .55; cursor: wait; }
    pre { margin: 0; max-height: 300px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; font: 12px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace; }
    .status { border-radius: 999px; padding: 4px 9px; font-size: 12px; background: #e8ecf5; color: #334155; }
    .status.ok { background: #d8f5e4; color: #146c3a; }
    .status.bad { background: #fee4e2; color: #b42318; }
    .fields { display: grid; gap: 8px; }
    .field { display: grid; gap: 5px; border-top: 1px solid var(--color-border-primary, #e5e7eb); padding-top: 8px; }
    .field:first-child { border-top: 0; padding-top: 0; }
    .field small { color: var(--color-text-secondary, #667085); }
	    .section-title { margin: 0 0 8px; font-size: 13px; }
	    details { margin-top: 12px; border-top: 1px solid var(--color-border-primary, #e5e7eb); padding-top: 10px; }
	    summary { cursor: pointer; font-size: 13px; font-weight: 650; }
	    details label { margin-top: 9px; }
	    #refs { margin-top: 8px; max-height: 130px; }
    @media (max-width: 760px) { .grid { grid-template-columns: 1fr; } #source { min-height: 240px; } }
  </style>
</head>
<body>
<main>
  <header>
    <div><h1>Yaksha EXP Console</h1><div class="muted">单文件 Yaklang EXP · MCP 直连 Yaksha · 不访问宿主文件系统</div><div id="identity" class="muted">未绑定 Revision</div></div>
    <span id="status" class="status">等待输入</span>
  </header>
  <div class="grid">
    <section class="panel">
      <label>main.yak
        <textarea id="source" spellcheck="false">target = cli.String("target", cli.setVerboseName("目标地址"), cli.setRequired(true))
cli.check()
yaksha.result({"vulnerable": false, "target": target})</textarea>
      </label>
      <div class="actions">
        <label>动作
          <select id="action">
            <option value="inspect">inspect</option>
            <option value="validate">validate</option>
            <option value="test">test</option>
            <option value="debug">debug</option>
            <option value="run">run</option>
          </select>
        </label>
        <label>超时（毫秒）<input id="timeout" type="number" min="0" max="120000" value="15000"></label>
        <button id="execute" type="button">执行</button>
      </div>
    </section>
    <aside class="panel">
      <h2 class="section-title">声明式参数 UI</h2>
      <div id="fields" class="fields"><span class="muted">先运行 inspect 解析 cli.* 声明</span></div>
      <label style="margin-top:12px">参数 JSON<textarea id="params" spellcheck="false">{"target":"https://authorized.invalid"}</textarea></label>
	      <label id="test-wrap" style="margin-top:12px">Fixture 测试 JSON<textarea id="tests" spellcheck="false">[]</textarea></label>
	      <details>
	        <summary>Resolver 与网络出口</summary>
	        <div class="muted">依赖与 Asset 由调用方密封传入；目标授权与本次出口模式相互独立，默认禁用网络。</div>
	        <pre id="refs" class="muted">inspect 后显示源码引用</pre>
	        <label>依赖闭包 JSON<textarea id="dependencies" spellcheck="false">[]</textarea></label>
	        <label>Asset JSON<textarea id="assets" spellcheck="false">[]</textarea></label>
	        <label>精确网络目标 JSON<textarea id="targets" spellcheck="false">[]</textarea></label>
	        <label>本次出口模式<select id="egress-mode"><option value="disabled">disabled</option><option value="direct">direct</option><option value="socks5">socks5</option><option value="agent">agent</option></select></label>
	        <label id="proxy-wrap" hidden>本次 SOCKS5 出口（仅本次写入，不回填）<input id="proxy" type="password" autocomplete="new-password" placeholder="socks5://user:password@proxy.example:1080"></label>
	        <div id="agent-wrap" hidden><label>Agent ID<input id="agent-id" autocomplete="off" placeholder="明确指定在线 Agent"></label><label><input id="risk-confirmed" type="checkbox"> 我已确认本次 Agent 出口及目标风险</label></div>
	      </details>
    </aside>
  </div>
  <section class="panel"><h2 class="section-title">诊断 / 结果 / Evidence / 日志 / Trace</h2><pre id="output">尚未执行</pre></section>
</main>
<script>
(function () {
  'use strict';
  var nextId = 1;
  var pending = new Map();
  var source = document.getElementById('source');
  var action = document.getElementById('action');
  var params = document.getElementById('params');
	  var tests = document.getElementById('tests');
	  var dependencies = document.getElementById('dependencies');
	  var assets = document.getElementById('assets');
	  var targets = document.getElementById('targets');
	  var egressMode = document.getElementById('egress-mode');
	  var proxyWrap = document.getElementById('proxy-wrap');
	  var proxy = document.getElementById('proxy');
	  var agentWrap = document.getElementById('agent-wrap');
	  var agentID = document.getElementById('agent-id');
	  var riskConfirmed = document.getElementById('risk-confirmed');
	  var refs = document.getElementById('refs');
  var timeout = document.getElementById('timeout');
  var execute = document.getElementById('execute');
  var output = document.getElementById('output');
  var status = document.getElementById('status');
  var fields = document.getElementById('fields');
	var identity = document.getElementById('identity');
	var boundContext = {};

	function syncEgressMode() {
	  var socks5 = egressMode.value === 'socks5';
	  var agent = egressMode.value === 'agent';
	  proxyWrap.hidden = !socks5;
	  agentWrap.hidden = !agent;
	  if (!socks5) proxy.value = '';
	  if (!agent) { agentID.value = ''; riskConfirmed.checked = false; }
	}

  function sendRequest(method, value) {
    var id = nextId++;
    window.parent.postMessage({jsonrpc: '2.0', id: id, method: method, params: value || {}}, '*');
    return new Promise(function (resolve, reject) { pending.set(id, {resolve: resolve, reject: reject}); });
  }
  function sendNotification(method, value) {
    window.parent.postMessage({jsonrpc: '2.0', method: method, params: value || {}}, '*');
  }
  function setStatus(value, bad) {
    status.textContent = value;
    status.className = 'status ' + (bad ? 'bad' : value === 'Succeeded' ? 'ok' : '');
  }
  function parseJSON(text, label) {
    try { return JSON.parse(text); } catch (error) { throw new Error(label + ' 不是有效 JSON：' + error.message); }
  }
  function renderResult(value) {
    if (!value || typeof value !== 'object') return;
	if (value.context) {
	  boundContext = value.context;
	  renderIdentity();
	}
	if (value.isError) {
	  setStatus('失败', true);
	  output.textContent = JSON.stringify(value, null, 2);
	  return;
	}
    setStatus(String(value.status || '已返回'), value.status && value.status !== 'Succeeded');
    output.textContent = JSON.stringify(value, null, 2);
	    if (value.inspection) {
	      renderFields(value.inspection.parameters || []);
	      refs.textContent = JSON.stringify({dependencies: value.inspection.dependencies || [], asset_refs: value.inspection.asset_refs || []}, null, 2);
	    }
  }
	function renderIdentity() {
	  var hash = boundContext.source_sha256 ? String(boundContext.source_sha256) : '';
	  if (boundContext.exp_id && boundContext.revision) {
		identity.textContent = String(boundContext.exp_id) + ' · Revision ' + String(boundContext.revision) + (hash ? ' · sha256 ' + hash.slice(0, 12) : '');
		return;
	  }
	  identity.textContent = hash ? '内存源码 · sha256 ' + hash.slice(0, 12) : '未绑定 Revision';
	}
  function renderFields(items) {
	fields.textContent = '';
    if (!items.length) {
      fields.textContent = '没有声明 cli.* 参数';
      fields.className = 'fields muted';
      return;
    }
    fields.className = 'fields';
	var current = {};
	try { current = JSON.parse(params.value || '{}'); } catch (_) {}
	items.forEach(function (item) {
	  var type = String(item.type || '').toLowerCase();
	  var row = document.createElement('div');
	  row.className = 'field';
      var title = document.createElement('strong');
      title.textContent = (item.verbose_name || item.name) + ' · ' + item.type + (item.required ? ' · 必填' : '');
	  var help = document.createElement('small');
	  help.textContent = item.help || ('参数名：' + item.name);
	  var control;
	  if (item.options && item.options.length) {
		control = document.createElement('select');
		control.multiple = Boolean(item.multiple_select);
		if (!item.required && !control.multiple) {
		  var empty = document.createElement('option');
		  empty.value = '';
		  empty.textContent = '未设置';
		  control.appendChild(empty);
		}
		item.options.forEach(function (option) {
		  var element = document.createElement('option');
		  element.value = String(option.value);
		  element.textContent = option.label || String(option.value);
		  control.appendChild(element);
		});
	  } else if (type === 'boolean') {
		control = document.createElement('input');
		control.type = 'checkbox';
	  } else if (type === 'text' || type === 'string_array') {
		control = document.createElement('textarea');
		control.style.minHeight = '64px';
	  } else {
		control = document.createElement('input');
		control.type = type === 'integer' || type === 'number' ? 'number' : 'text';
		if (type === 'number') control.step = 'any';
	  }
	  control.dataset.paramName = item.name;
	  control.dataset.paramType = type;
	  control.dataset.required = item.required ? 'true' : 'false';
	  var initial = Object.prototype.hasOwnProperty.call(current, item.name) ? current[item.name] : (item.has_default ? item.default : undefined);
	  setControlValue(control, initial, item);
	  control.addEventListener('input', syncParamsFromFields);
	  row.appendChild(title);
	  row.appendChild(help);
	  row.appendChild(control);
	  fields.appendChild(row);
	});
	syncParamsFromFields();
  }
	function setControlValue(control, value, item) {
	  if (value === undefined || value === null) return;
	  if (control.type === 'checkbox') { control.checked = Boolean(value); return; }
	  if (control.multiple) {
		var selected = Array.isArray(value) ? value.map(String) : String(value).split(',').map(function (v) { return v.trim(); });
		Array.prototype.forEach.call(control.options, function (option) { option.selected = selected.indexOf(option.value) >= 0; });
		return;
	  }
	  control.value = Array.isArray(value) ? value.join(',') : String(value);
	}
	function syncParamsFromFields() {
	  var value = {};
	  Array.prototype.forEach.call(fields.querySelectorAll('[data-param-name]'), function (control) {
		var name = control.dataset.paramName;
		var type = control.dataset.paramType;
		var raw;
		if (control.type === 'checkbox') raw = control.checked;
		else if (control.multiple) raw = Array.prototype.filter.call(control.options, function (o) { return o.selected; }).map(function (o) { return o.value; });
		else raw = control.value;
		if (raw === '' && control.dataset.required !== 'true') return;
		if (type === 'integer') raw = Number.parseInt(raw, 10);
		else if (type === 'number') raw = Number.parseFloat(raw);
		else if (type === 'string_array' && !Array.isArray(raw)) raw = String(raw).split(',').map(function (v) { return v.trim(); }).filter(Boolean);
		value[name] = raw;
	  });
	  params.value = JSON.stringify(value, null, 2);
	}
  function applyToolInput(value) {
    var a = value && value.arguments ? value.arguments : value;
    if (!a || typeof a !== 'object') return;
    if (typeof a.script === 'string') source.value = a.script;
    if (typeof a.action === 'string') action.value = a.action;
    if (a.params) params.value = JSON.stringify(a.params, null, 2);
	    if (a.test_cases) tests.value = JSON.stringify(a.test_cases, null, 2);
	    if (a.dependencies) dependencies.value = JSON.stringify(a.dependencies, null, 2);
	    if (a.assets) assets.value = JSON.stringify(a.assets, null, 2);
	    if (a.network_targets) targets.value = JSON.stringify(a.network_targets, null, 2);
	    if (a.egress && ['disabled', 'direct', 'socks5', 'agent'].indexOf(a.egress.mode) >= 0) egressMode.value = a.egress.mode;
	    if (a.egress && a.egress.mode === 'agent') { agentID.value = a.egress.agent_id || ''; riskConfirmed.checked = Boolean(a.egress.risk_confirmed); }
	    proxy.value = '';
	    syncEgressMode();
    if (a.timeout_ms) timeout.value = String(a.timeout_ms);
	if (a.exp_id && a.revision && a.source_sha256) {
	  boundContext = {exp_id: a.exp_id, revision: a.revision, source_sha256: a.source_sha256};
	} else {
	  boundContext = {};
	}
	renderIdentity();
  }
  function applyToolResult(value) {
    var result = value && value.structuredContent ? value.structuredContent : value;
    if (result && result.result && result.content) result = result.structuredContent || result;
    renderResult(result);
  }
  window.addEventListener('message', function (event) {
    var message = event.data;
	if (event.source !== window.parent || !message || message.jsonrpc !== '2.0') return;
    if (message.method === undefined && message.id !== undefined && pending.has(message.id)) {
      var task = pending.get(message.id);
      pending.delete(message.id);
      if (message.error) task.reject(new Error(message.error.message || JSON.stringify(message.error)));
      else task.resolve(message.result);
      return;
    }
    if (message.method === 'ui/notifications/tool-input') applyToolInput(message.params);
    if (message.method === 'ui/notifications/tool-result') applyToolResult(message.params);
	if (message.method === 'ui/notifications/tool-cancelled') {
	  setStatus('已取消', true);
	  output.textContent = message.params && message.params.reason ? String(message.params.reason) : '工具执行已取消';
	}
	if (message.method === 'ui/resource-teardown' && message.id !== undefined) {
	  window.parent.postMessage({jsonrpc: '2.0', id: message.id, result: {}}, '*');
	}
  });
  execute.addEventListener('click', async function () {
    execute.disabled = true;
    setStatus('执行中', false);
    try {
      var args = {action: action.value, script: source.value, timeout_ms: Number(timeout.value || 0)};
	  if (boundContext.exp_id && boundContext.revision && boundContext.source_sha256) {
		args.exp_id = boundContext.exp_id;
		args.revision = boundContext.revision;
		args.source_sha256 = boundContext.source_sha256;
	  }
		  if (action.value !== 'inspect' && action.value !== 'test') args.params = parseJSON(params.value || '{}', '参数');
	      if (action.value === 'test') args.test_cases = parseJSON(tests.value || '[]', '测试用例');
	      if (action.value !== 'inspect') {
	        args.dependencies = parseJSON(dependencies.value || '[]', '依赖闭包');
	        args.assets = parseJSON(assets.value || '[]', 'Asset');
	        args.network_targets = parseJSON(targets.value || '[]', '网络目标');
	        args.egress = {mode: egressMode.value};
	        if (egressMode.value === 'socks5') {
	          if (!proxy.value.trim()) throw new Error('SOCKS5 模式需要填写本次代理地址');
	          args.egress.socks5_proxy = proxy.value.trim();
	        }
	        if (egressMode.value === 'agent') {
	          if (!agentID.value.trim() || !riskConfirmed.checked) throw new Error('Agent 模式需要明确 Agent ID 并确认风险');
	          args.egress.agent_id = agentID.value.trim();
	          args.egress.risk_confirmed = true;
	        }
	      }
      var result = await sendRequest('tools/call', {name: 'argus_yaksha_exp', arguments: args});
      applyToolResult(result);
    } catch (error) {
      setStatus('失败', true);
      output.textContent = error.message;
    } finally { execute.disabled = false; }
	  });
	  egressMode.addEventListener('change', syncEgressMode);
	  syncEgressMode();
  sendRequest('ui/initialize', {
    protocolVersion: '2026-01-26',
    appInfo: {name: 'Yaksha EXP Console', version: '0.1.0'},
    appCapabilities: {availableDisplayModes: ['inline', 'fullscreen']}
  }).then(function () {
    sendNotification('ui/notifications/initialized', {});
  }).catch(function (error) {
    setStatus('宿主不支持 MCP App', true);
    output.textContent = error.message;
  });
}());
</script>
</body>
</html>`
