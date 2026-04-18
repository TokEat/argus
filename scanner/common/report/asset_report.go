package report

import (
	"bufio"
	"dddd/scanner/structs"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AssetEntry represents a parsed line from result.txt
type AssetEntry struct {
	EntryType   string // Web, Finger, Nmap, Alive, GoPoc, etc.
	URL         string
	StatusCode  string
	Title       string
	Fingerprint []string
	Protocol    string
	RawLine     string
}

// parseResultLine parses a single line from result.txt into an AssetEntry
func parseResultLine(line string) *AssetEntry {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	entry := &AssetEntry{RawLine: line}

	if strings.HasPrefix(line, "[Web] ") {
		// Format: [Web] [STATUS] URL [Title]
		entry.EntryType = "Web"
		rest := line[6:] // strip "[Web] "
		if strings.HasPrefix(rest, "[") {
			end := strings.Index(rest, "] ")
			if end > 0 {
				entry.StatusCode = rest[1:end]
				rest = rest[end+2:]
			}
		}
		// rest is now: URL [Title] or just URL
		if idx := strings.Index(rest, " ["); idx > 0 {
			entry.URL = strings.TrimSpace(rest[:idx])
			titlePart := rest[idx+2:]
			if strings.HasSuffix(titlePart, "]") {
				entry.Title = titlePart[:len(titlePart)-1]
			}
		} else {
			entry.URL = strings.TrimSpace(rest)
		}

	} else if strings.HasPrefix(line, "[Finger] ") {
		// Format: [Finger] URL [STATUS] [Tech,Tech,...] [Title]
		entry.EntryType = "Finger"
		rest := line[9:] // strip "[Finger] "
		// First token is URL (up to first ' [')
		if idx := strings.Index(rest, " ["); idx > 0 {
			entry.URL = strings.TrimSpace(rest[:idx])
			rest = rest[idx+1:]
		} else {
			entry.URL = strings.TrimSpace(rest)
			return entry
		}
		// parse remaining [STATUS] [Tech,...] [Title] blocks
		for strings.HasPrefix(rest, "[") {
			end := strings.Index(rest, "]")
			if end < 0 {
				break
			}
			block := rest[1:end]
			rest = strings.TrimSpace(rest[end+1:])
			// Determine what this block is
			if isStatusCode(block) {
				entry.StatusCode = block
			} else if strings.Contains(block, ",") || isFingerprint(block) {
				// Technology list
				for _, f := range strings.Split(block, ",") {
					f = strings.TrimSpace(f)
					if f != "" {
						entry.Fingerprint = append(entry.Fingerprint, f)
					}
				}
			} else {
				// single fingerprint or title
				if entry.Fingerprint != nil {
					// Already have fingerprints, so this is the title
					entry.Title = block
				} else {
					entry.Fingerprint = append(entry.Fingerprint, block)
				}
			}
		}

	} else if strings.HasPrefix(line, "[Nmap] ") {
		entry.EntryType = "Nmap"
		rest := line[7:]
		// Format: proto://IP:Port
		entry.URL = rest
		if idx := strings.Index(rest, "://"); idx > 0 {
			entry.Protocol = rest[:idx]
		}

	} else if strings.HasPrefix(line, "[Alive] ") {
		entry.EntryType = "Alive"
		entry.URL = strings.TrimSpace(line[8:])

	} else if strings.HasPrefix(line, "[PortScan] ") {
		entry.EntryType = "PortScan"
		entry.URL = strings.TrimSpace(line[11:])

	} else if strings.HasPrefix(line, "[GoPoc] ") || strings.HasPrefix(line, "[CRITICAL] ") ||
		strings.HasPrefix(line, "[HIGH] ") || strings.HasPrefix(line, "[MEDIUM] ") ||
		strings.HasPrefix(line, "[LOW] ") || strings.HasPrefix(line, "[INFO] ") {
		entry.EntryType = "Vuln"
		entry.URL = line

	} else {
		entry.EntryType = "Other"
		entry.URL = line
	}

	return entry
}

// isStatusCode checks if a string looks like an HTTP status code
func isStatusCode(s string) bool {
	if len(s) != 3 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// isFingerprint checks if a string is likely a fingerprint (not a title)
func isFingerprint(s string) bool {
	// Heuristic: fingerprints tend to be short product names without spaces
	return len(s) < 40 && !strings.Contains(s, " ")
}

// GenerateAssetReport reads the output result file and generates an HTML asset report
func GenerateAssetReport() {
	outputFile := structs.GlobalConfig.OutputFile
	if outputFile == "" {
		return
	}

	// Check if result file exists
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		return
	}

	// Derive asset report filename
	ext := filepath.Ext(outputFile)
	base := outputFile[:len(outputFile)-len(ext)]
	assetReportFile := base + "_assets.html"

	// Read and parse result.txt
	f, err := os.Open(outputFile)
	if err != nil {
		fmt.Printf("Open %s error: %v\n", outputFile, err)
		return
	}
	defer f.Close()

	var entries []*AssetEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		entry := parseResultLine(line)
		if entry != nil && entry.EntryType != "Other" && entry.EntryType != "" {
			entries = append(entries, entry)
		}
	}

	if len(entries) == 0 {
		return
	}

	// Generate HTML
	htmlContent := generateAssetHTML(entries, outputFile)

	// Write to file
	err = os.WriteFile(assetReportFile, []byte(htmlContent), 0666)
	if err != nil {
		fmt.Printf("Write asset report %s error: %v\n", assetReportFile, err)
		return
	}

	fmt.Printf("[+] 资产报告已生成: %s\n", assetReportFile)
}

func generateAssetHTML(entries []*AssetEntry, sourceFile string) string {
	// Count by type
	webCount := 0
	fingerCount := 0
	portCount := 0
	aliveCount := 0
	vulnCount := 0

	for _, e := range entries {
		switch e.EntryType {
		case "Web":
			webCount++
		case "Finger":
			fingerCount++
		case "Nmap", "PortScan":
			portCount++
		case "Alive":
			aliveCount++
		case "Vuln":
			vulnCount++
		}
	}

	now := time.Now().Format("2006-01-02 15:04:05")

	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>dddd 资产报告</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft Yahei",Arial,sans-serif;background:#1c1b19;color:#FEFEFF;font-size:14px;min-width:900px;}
a{color:#58a6ff;text-decoration:none;}
a:hover{text-decoration:underline;}
.header{background:#0867C1;padding:18px 24px;font-size:22px;font-weight:bold;display:flex;align-items:center;justify-content:space-between;}
.header .ts{font-size:12px;font-weight:normal;color:rgba(255,255,255,0.7);}
.stats{display:flex;gap:12px;padding:16px 24px;background:#2a2927;border-bottom:1px solid #333;flex-wrap:wrap;}
.stat-card{background:#1c1b19;border:1px solid #444;border-radius:6px;padding:10px 18px;min-width:110px;text-align:center;}
.stat-card .num{font-size:26px;font-weight:bold;}
.stat-card .label{font-size:11px;color:#aaa;margin-top:2px;}
.num-all{color:#fff;}
.num-web{color:#58a6ff;}
.num-finger{color:#3fb950;}
.num-port{color:#d2a8ff;}
.num-alive{color:#f0883e;}
.num-vuln{color:#ff6b6b;}
.toolbar{padding:12px 24px;background:#242320;border-bottom:1px solid #333;display:flex;gap:8px;flex-wrap:wrap;align-items:center;position:sticky;top:0;z-index:999;}
.filter-btn{display:inline-block;padding:4px 14px;border:1px solid #555;border-radius:4px;cursor:pointer;font-size:12px;font-weight:bold;color:#ccc;background:#1c1b19;transition:all 0.2s;}
.filter-btn:hover{background:#333;}
.filter-btn.active{background:#0867C1;border-color:#0867C1;color:#fff;}
.search-box{flex:1;max-width:320px;padding:4px 10px;background:#1c1b19;border:1px solid #555;border-radius:4px;color:#fff;font-size:12px;outline:none;}
.search-box:focus{border-color:#0867C1;}
.table-wrap{padding:0 24px 24px;}
table{width:100%;border-collapse:collapse;margin-top:16px;}
th{background:#2a2927;color:#aaa;text-align:left;padding:8px 10px;font-size:12px;border-bottom:1px solid #444;position:sticky;top:44px;z-index:100;}
td{padding:7px 10px;border-bottom:1px solid #2a2927;font-size:13px;vertical-align:top;word-break:break-all;}
tr:hover td{background:#242320;}
.tag{display:inline-block;padding:1px 7px;border-radius:3px;font-size:11px;margin:1px;font-weight:bold;}
.tag-web{background:#0d3b73;color:#58a6ff;border:1px solid #1f5fa3;}
.tag-finger{background:#0b3320;color:#3fb950;border:1px solid #1a6640;}
.tag-port{background:#1e1040;color:#d2a8ff;border:1px solid #5530a0;}
.tag-alive{background:#3d2000;color:#f0883e;border:1px solid #804500;}
.tag-vuln{background:#3d0000;color:#ff6b6b;border:1px solid #800000;}
.badge{display:inline-block;background:#555;color:#fff;border-radius:10px;padding:1px 6px;font-size:11px;margin-left:4px;}
.fp-tag{display:inline-block;background:#1a3040;color:#79c0ff;border:1px solid #2a5070;border-radius:3px;padding:1px 6px;font-size:11px;margin:1px;}
.status-ok{color:#3fb950;}
.status-redir{color:#f0883e;}
.status-err{color:#ff6b6b;}
.hidden{display:none;}
.src-note{color:#666;font-size:11px;padding:10px 24px;}
</style>
</head>
<body>
<div class="header">
  <span>🛡️ &nbsp;dddd 资产报告</span>
  <span class="ts">`)
	sb.WriteString(html.EscapeString(now))
	sb.WriteString(`</span>
</div>
<div class="stats">
  <div class="stat-card"><div class="num num-all">`)
	sb.WriteString(fmt.Sprintf("%d", len(entries)))
	sb.WriteString(`</div><div class="label">总资产</div></div>
  <div class="stat-card"><div class="num num-web">`)
	sb.WriteString(fmt.Sprintf("%d", webCount))
	sb.WriteString(`</div><div class="label">Web 服务</div></div>
  <div class="stat-card"><div class="num num-finger">`)
	sb.WriteString(fmt.Sprintf("%d", fingerCount))
	sb.WriteString(`</div><div class="label">指纹识别</div></div>
  <div class="stat-card"><div class="num num-port">`)
	sb.WriteString(fmt.Sprintf("%d", portCount))
	sb.WriteString(`</div><div class="label">开放端口</div></div>
  <div class="stat-card"><div class="num num-alive">`)
	sb.WriteString(fmt.Sprintf("%d", aliveCount))
	sb.WriteString(`</div><div class="label">存活主机</div></div>
  <div class="stat-card"><div class="num num-vuln">`)
	sb.WriteString(fmt.Sprintf("%d", vulnCount))
	sb.WriteString(`</div><div class="label">漏洞信息</div></div>
</div>
<div class="toolbar">
  <span class="filter-btn active" data-type="all">全部 <span class="badge" id="cnt-all">0</span></span>
  <span class="filter-btn" data-type="Web">Web <span class="badge" id="cnt-web">0</span></span>
  <span class="filter-btn" data-type="Finger">指纹 <span class="badge" id="cnt-finger">0</span></span>
  <span class="filter-btn" data-type="Nmap">端口 <span class="badge" id="cnt-port">0</span></span>
  <span class="filter-btn" data-type="Alive">存活 <span class="badge" id="cnt-alive">0</span></span>
  <span class="filter-btn" data-type="Vuln">漏洞 <span class="badge" id="cnt-vuln">0</span></span>
  <input class="search-box" id="searchBox" type="text" placeholder="搜索 URL / 标题 / 指纹...  (Ctrl+F 或 /)">
  <span id="match-count" style="display:none;color:#f0b429;font-size:12px;margin-left:4px;white-space:nowrap;"></span>
  <span style="color:#555;font-size:11px;margin-left:8px;">ESC 清空</span>
</div>
<div class="table-wrap">
<p class="src-note">数据来源: `)
	sb.WriteString(html.EscapeString(sourceFile))
	sb.WriteString(`</p>
<table>
<thead>
<tr>
  <th style="width:4%">#</th>
  <th style="width:8%">类型</th>
  <th style="width:36%">URL / 主机</th>
  <th style="width:7%">状态码</th>
  <th style="width:20%">标题</th>
  <th style="width:25%">指纹 / 技术栈</th>
</tr>
</thead>
<tbody id="assetTbody">
`)

	for i, e := range entries {
		typeClass := ""
		typeLabel := ""
		displayType := e.EntryType
		switch e.EntryType {
		case "Web":
			typeClass = "tag-web"
			typeLabel = "Web"
		case "Finger":
			typeClass = "tag-finger"
			typeLabel = "指纹"
		case "Nmap", "PortScan":
			typeClass = "tag-port"
			typeLabel = "端口"
			displayType = "Nmap"
		case "Alive":
			typeClass = "tag-alive"
			typeLabel = "存活"
		case "Vuln":
			typeClass = "tag-vuln"
			typeLabel = "漏洞"
		default:
			typeClass = "tag-web"
			typeLabel = e.EntryType
		}

		statusClass := ""
		if e.StatusCode != "" {
			if strings.HasPrefix(e.StatusCode, "2") {
				statusClass = "status-ok"
			} else if strings.HasPrefix(e.StatusCode, "3") {
				statusClass = "status-redir"
			} else if strings.HasPrefix(e.StatusCode, "4") || strings.HasPrefix(e.StatusCode, "5") {
				statusClass = "status-err"
			}
		}

		// Build fingerprint tags
		var fpHTML strings.Builder
		for _, fp := range e.Fingerprint {
			fpHTML.WriteString(`<span class="fp-tag">`)
			fpHTML.WriteString(html.EscapeString(fp))
			fpHTML.WriteString(`</span>`)
		}

		urlDisplay := e.URL
		urlHTML := ""
		if strings.HasPrefix(e.URL, "http://") || strings.HasPrefix(e.URL, "https://") {
			urlHTML = fmt.Sprintf(`<a href="%s" target="_blank">%s</a>`,
				html.EscapeString(e.URL), html.EscapeString(urlDisplay))
		} else {
			urlHTML = html.EscapeString(urlDisplay)
		}

		sb.WriteString(fmt.Sprintf(
			`<tr class="asset-row" data-type="%s">
  <td>%d</td>
  <td><span class="tag %s">%s</span></td>
  <td>%s</td>
  <td class="%s">%s</td>
  <td>%s</td>
  <td>%s</td>
</tr>`,
			html.EscapeString(displayType),
			i+1,
			typeClass, typeLabel,
			urlHTML,
			statusClass, html.EscapeString(e.StatusCode),
			html.EscapeString(e.Title),
			fpHTML.String(),
		))
		sb.WriteString("\n")
	}

	sb.WriteString(`</tbody>
</table>
</div>
<script>
(function(){
  var rows = document.querySelectorAll('.asset-row');
  var btns = document.querySelectorAll('.filter-btn');
  var searchBox = document.getElementById('searchBox');
  var currentType = 'all';

  function countType(type) {
    var n = 0;
    rows.forEach(function(r){ if(type === 'all' || r.dataset.type === type || (type === 'Nmap' && (r.dataset.type === 'Nmap' || r.dataset.type === 'PortScan'))) n++; });
    return n;
  }
  document.getElementById('cnt-all').textContent = rows.length;
  document.getElementById('cnt-web').textContent = countType('Web');
  document.getElementById('cnt-finger').textContent = countType('Finger');
  document.getElementById('cnt-port').textContent = countType('Nmap');
  document.getElementById('cnt-alive').textContent = countType('Alive');
  document.getElementById('cnt-vuln').textContent = countType('Vuln');

  // --- 搜索高亮 ---
  var matchCount = document.getElementById('match-count');

  // 存储每个搜索单元格的原始 HTML（只存可搜索的 td）
  var cellsPerRow = [];
  rows.forEach(function(r) {
    // 取第3~6列（URL、状态码、标题、指纹），跳过序号和类型标签列
    var tds = r.querySelectorAll('td');
    var searchCells = [];
    for (var i = 2; i < tds.length; i++) {
      searchCells.push({ el: tds[i], orig: tds[i].innerHTML });
    }
    cellsPerRow.push(searchCells);
  });

  function escapeRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function applyFilters() {
    var q = searchBox.value.trim();
    var matchTotal = 0;

    rows.forEach(function(r, idx) {
      var cells = cellsPerRow[idx];
      // 先恢复原始 HTML
      cells.forEach(function(c) { c.el.innerHTML = c.orig; });

      var typeMatch = currentType === 'all' || r.dataset.type === currentType ||
        (currentType === 'Nmap' && (r.dataset.type === 'Nmap' || r.dataset.type === 'PortScan'));

      var textMatch = true;
      if (q !== '') {
        // 在原始文本中检测是否包含关键词
        var rowText = r.textContent.toLowerCase();
        textMatch = rowText.indexOf(q.toLowerCase()) >= 0;

        if (textMatch) {
          // 高亮匹配文本
          var re = new RegExp('(' + escapeRegex(q) + ')', 'gi');
          cells.forEach(function(c) {
            // 只对文本节点做替换，避免破坏 HTML 标签属性
            c.el.innerHTML = c.el.innerHTML.replace(re,
              '<mark style="background:#f0b429;color:#000;border-radius:2px;padding:0 2px;">$1</mark>');
          });
          matchTotal++;
        }
      } else {
        if (typeMatch) matchTotal++;
      }

      r.style.display = (typeMatch && textMatch) ? '' : 'none';
    });

    // 更新匹配数显示
    if (q !== '') {
      matchCount.textContent = matchTotal + ' 处匹配';
      matchCount.style.display = 'inline';
    } else {
      matchCount.style.display = 'none';
    }
  }

  btns.forEach(function(btn) {
    btn.addEventListener('click', function() {
      btns.forEach(function(b){ b.classList.remove('active'); });
      btn.classList.add('active');
      currentType = btn.dataset.type;
      applyFilters();
    });
  });

  searchBox.addEventListener('input', applyFilters);

  // ESC 清空搜索
  searchBox.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      searchBox.value = '';
      applyFilters();
      searchBox.blur();
    }
  });

  // Ctrl+F 或 / 聚焦搜索框
  document.addEventListener('keydown', function(e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
      e.preventDefault();
      searchBox.focus();
      searchBox.select();
    } else if (e.key === '/' && document.activeElement !== searchBox) {
      e.preventDefault();
      searchBox.focus();
      searchBox.select();
    }
  });
})();
</script>
</body>
</html>
`)

	return sb.String()
}
