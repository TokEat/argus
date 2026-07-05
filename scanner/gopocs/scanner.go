package gopocs

import (
	"dddd/scanner/common/report"
	"dddd/scanner/ddout"
	"dddd/scanner/structs"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
)

// NucleiResult keeps the GoPoc package independent from nuclei output types.
type NucleiResult struct {
	TemplateID string
	Matched    string
	URL        string
}

type scanTask struct {
	Name string
	Info structs.HostInfo
}

type dispatcher struct {
	progressMu   sync.Mutex
	currentCount int
	results      []structs.GoPocsResultType
	resultsMu    sync.Mutex
	allCount     int
	emit         func(structs.OutputMessage)
}

func (d *dispatcher) addScan(name string, info structs.HostInfo, ch chan struct{}, wg *sync.WaitGroup) {
	d.progressMu.Lock()
	d.currentCount++
	currentCount := d.currentCount
	allCount := d.allCount
	d.progressMu.Unlock()

	if currentCount%10 == 0 || currentCount == allCount {
		gologger.Info().Msgf("[GoPoc] 当前进度: %v %v [%v/%v]", name, info.Host+":"+info.Ports, currentCount, allCount)
	}

	ch <- struct{}{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { <-ch }()
		info.WriteResult = d.writeResult
		info.Emit = d.emit
		d.scanFunc(name, &info)
	}()
}

func (d *dispatcher) scanFunc(name string, info *structs.HostInfo) {
	defer func() {
		if r := recover(); r != nil {
			gologger.Error().Msgf("[GoPoc] Plugin '%s' panic: %v", name, r)
		}
	}()
	plugin, ok := PluginList[name]
	if !ok || plugin == nil {
		gologger.Error().Msgf("[GoPoc] Plugin '%s' not found in PluginList", name)
		return
	}
	f := reflect.ValueOf(plugin)
	in := []reflect.Value{reflect.ValueOf(info)}
	f.Call(in)
}

func (d *dispatcher) writeResult(result structs.GoPocsResultType) {
	d.resultsMu.Lock()
	d.results = append(d.results, result)
	d.resultsMu.Unlock()
	report.AddResultByGoPocResult(result)
}

func (d *dispatcher) snapshotResults() []structs.GoPocsResultType {
	d.resultsMu.Lock()
	defer d.resultsMu.Unlock()
	return append([]structs.GoPocsResultType(nil), d.results...)
}

func GoPocsDispatcher(nucleiResults []NucleiResult) {
	structs.GoPocsResults = Dispatch(
		structs.GlobalIPPortMap,
		structs.GlobalConfig.GoPocThreads,
		structs.GlobalConfig.Password,
		structs.GlobalConfig.PasswordFile,
		nucleiResults,
		nil, // no emit in CLI global fallback
	)
}

func Dispatch(ipPortMap map[string]string, goPocThreads int, password string, passwordFile string, nucleiResults []NucleiResult, emit func(structs.OutputMessage)) []structs.GoPocsResultType {
	if len(ipPortMap) == 0 && len(nucleiResults) == 0 {
		return nil
	}

	InitDictionaries()

	if emit == nil {
		emit = func(msg structs.OutputMessage) {
			ddout.FormatOutput(msg)
		}
	}

	dispatcher := &dispatcher{
		emit: emit,
	}

	plan := buildScanPlan(ipPortMap, password, passwordFile, dispatcher.writeResult)
	dispatcher.allCount = len(plan) + len(nucleiResults)
	if dispatcher.allCount == 0 {
		return nil
	}

	if goPocThreads <= 0 {
		goPocThreads = 1
	}

	var ch = make(chan struct{}, goPocThreads)
	var wg = sync.WaitGroup{}
	gologger.Info().Msg("Golang Poc引擎启动")

	for _, task := range plan {
		dispatcher.addScan(task.Name, task.Info, ch, &wg)
	}

	// Nuclei 检测到 Shiro 后自动触发 Shiro Key 爆破
	for _, result := range nucleiResults {
		if result.TemplateID == "shiro-detect" {
			dispatcher.addScan("Shiro-Key-Crack",
				structs.HostInfo{
					Url:          result.Matched,
					Password:     password,
					PasswordFile: passwordFile,
				},
				ch, &wg)
		}
		if isViewStateNucleiResult(result) {
			targetURL := result.Matched
			if targetURL == "" {
				targetURL = result.URL
			}
			if targetURL != "" {
				dispatcher.addScan("ViewState-Key-Crack",
					structs.HostInfo{
						Url:          targetURL,
						Password:     password,
						PasswordFile: passwordFile,
					},
					ch, &wg)
			}
		}
	}

	// 指纹匹配 viewstate 后自动触发 ViewState 密钥爆破。
	for host, fingers := range structs.GlobalResultMap {
		for _, f := range fingers {
			if strings.EqualFold(f, "viewstate") {
				dispatcher.addScan("ViewState-Key-Crack",
					structs.HostInfo{Url: host},
					ch, &wg)
			}
		}
	}

	wg.Wait()
	fmt.Printf("\r\033[K")
	gologger.Info().Msg("Golang Poc引擎扫描结束")

	results := dispatcher.snapshotResults()
	if len(results) > 0 {
		gologger.Info().Msg("发现漏洞汇总:")
		for _, res := range results {
			gologger.Info().Msgf("[%s] %s %s\n%s", res.Security, res.PocName, res.Target, res.InfoLeft)
		}
	}
	return results
}

func isViewStateNucleiResult(result NucleiResult) bool {
	return result.TemplateID == "yongyou_u9_viewstate"
}

func buildScanPlan(ipPortMap map[string]string, password string, passwordFile string, writeResult func(structs.GoPocsResultType)) []scanTask {
	var tasks []scanTask
	for hostPort, protocol := range ipPortMap {
		t := strings.Split(hostPort, ":")
		if len(t) != 2 {
			continue
		}
		host := t[0]
		port := t[1]

		// 减少无效爆破：Web 服务跳过 GoPoc 暴力破解。
		if protocol == "http" || protocol == "https" || protocol == "ssl/http" {
			continue
		}

		info := structs.HostInfo{
			Host:         host,
			Ports:        port,
			Password:     password,
			PasswordFile: passwordFile,
			WriteResult:  writeResult,
		}

		if protocol == "ssh" || port == "22" {
			tasks = append(tasks, scanTask{Name: "SSH-Crack", Info: info})
		}
		if protocol == "ftp" || port == "21" {
			tasks = append(tasks, scanTask{Name: "FTP-Crack", Info: info})
		}
		if protocol == "mysql" || port == "3306" {
			tasks = append(tasks, scanTask{Name: "Mysql-Crack", Info: info})
		}
		if protocol == "mssql" || port == "1433" {
			tasks = append(tasks, scanTask{Name: "Mssql-Crack", Info: info})
		}
		if protocol == "oracle" || port == "1521" {
			tasks = append(tasks, scanTask{Name: "Oracle-Crack", Info: info})
		}
		if protocol == "mongodb" || port == "27017" {
			tasks = append(tasks, scanTask{Name: "MongoDB-Crack", Info: info})
		}
		if protocol == "rdp" || port == "3389" {
			tasks = append(tasks, scanTask{Name: "RDP-Crack", Info: info})
		}
		if protocol == "redis" || port == "6379" {
			tasks = append(tasks, scanTask{Name: "Redis-Crack", Info: info})
		}
		if protocol == "smb" || port == "445" {
			tasks = append(tasks,
				scanTask{Name: "SMB-MS17-010", Info: info},
				scanTask{Name: "SMB-Crack", Info: info},
			)
		}
		if protocol == "postgresql" || port == "5432" {
			tasks = append(tasks, scanTask{Name: "PostgreSQL-Crack", Info: info})
		}
		if protocol == "telnet" || port == "23" {
			tasks = append(tasks, scanTask{Name: "Telnet-Crack", Info: info})
		}
		if protocol == "memcached" || port == "11211" {
			tasks = append(tasks, scanTask{Name: "Memcache-Crack", Info: info})
		}
		if protocol == "netbios" || port == "445" {
			tasks = append(tasks, scanTask{Name: "NetBios-GetHostInfo", Info: info})
		}
		if protocol == "rpc" {
			tasks = append(tasks, scanTask{Name: "RPC-GetHostInfo", Info: info})
		}
		if protocol == "jdwp" {
			tasks = append(tasks, scanTask{Name: "JDWP-Scan", Info: info})
		}
		if protocol == "adb" || port == "5555" {
			tasks = append(tasks, scanTask{Name: "ADB-Scan", Info: info})
		}
		if protocol == "vnc" || port == "5900" || port == "5901" {
			tasks = append(tasks, scanTask{Name: "VNC-Scan", Info: info})
		}
		if protocol == "rsync" || port == "873" {
			tasks = append(tasks, scanTask{Name: "Rsync-Scan", Info: info})
		}
		if protocol == "dm" || port == "5236" {
			tasks = append(tasks, scanTask{Name: "DM-Scan", Info: info})
		}
		if protocol == "kingbase" || port == "54321" {
			tasks = append(tasks, scanTask{Name: "Kingbase-Scan", Info: info})
		}
	}
	return tasks
}
