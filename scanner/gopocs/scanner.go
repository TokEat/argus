package gopocs

import (
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"sync"

	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/structs"

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

// Presentation controls terminal-only output for one GoPoc dispatch.  Its zero
// value preserves the interactive behaviour used by existing callers.
//
// MachineOutput must be set by a caller that owns a structured stdout stream.
// Findings still use the supplied emit callback (or ddout's fallback); only
// transient progress and diagnostics are suppressed.
type Presentation struct {
	MachineOutput bool
}

var presentations sync.Map // map[*structs.HostInfo]Presentation

func presentationFor(info *structs.HostInfo) Presentation {
	if info == nil {
		return Presentation{}
	}
	if value, ok := presentations.Load(info); ok {
		return value.(Presentation)
	}
	return Presentation{}
}

func shouldRenderProgress(info *structs.HostInfo) bool {
	return !presentationFor(info).MachineOutput
}

func printDiagnostic(info *structs.HostInfo, values ...interface{}) {
	if shouldRenderProgress(info) {
		fmt.Println(values...)
	}
}

type dispatcher struct {
	progressMu   sync.Mutex
	currentCount int
	results      []structs.GoPocsResultType
	resultsMu    sync.Mutex
	allCount     int
	emit         func(structs.OutputMessage)
	presentation Presentation
	executionMu  sync.Mutex
	executionErr []error
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
		presentations.Store(&info, d.presentation)
		defer presentations.Delete(&info)
		d.scanFunc(name, &info)
	}()
}

func (d *dispatcher) scanFunc(name string, info *structs.HostInfo) {
	defer func() {
		if r := recover(); r != nil {
			gologger.Error().Msgf("[GoPoc] Plugin '%s' panic: %v", name, r)
			d.recordExecutionError(fmt.Errorf("GoPoc plugin %q panicked", name))
		}
	}()
	plugin, ok := PluginList[name]
	if !ok || plugin == nil {
		gologger.Error().Msgf("[GoPoc] Plugin '%s' not found in PluginList", name)
		d.recordExecutionError(fmt.Errorf("GoPoc plugin %q is unavailable", name))
		return
	}
	f := reflect.ValueOf(plugin)
	in := []reflect.Value{reflect.ValueOf(info)}
	for _, output := range f.Call(in) {
		pluginErr, ok := output.Interface().(error)
		if ok && isSuccessfulSessionEvidenceError(pluginErr) {
			d.recordExecutionError(fmt.Errorf("GoPoc plugin %q could not preserve successful-session evidence: %w", name, pluginErr))
		}
	}
}

func (d *dispatcher) recordExecutionError(err error) {
	if err == nil {
		return
	}
	d.executionMu.Lock()
	d.executionErr = append(d.executionErr, err)
	d.executionMu.Unlock()
}

func (d *dispatcher) executionError() error {
	d.executionMu.Lock()
	defer d.executionMu.Unlock()
	return errors.Join(d.executionErr...)
}

func (d *dispatcher) writeResult(result structs.GoPocsResultType) {
	d.resultsMu.Lock()
	result.Exchanges = append([]structs.GoPocExchange(nil), result.Exchanges...)
	d.results = append(d.results, result)
	d.resultsMu.Unlock()
}

func (d *dispatcher) snapshotResults() []structs.GoPocsResultType {
	d.resultsMu.Lock()
	defer d.resultsMu.Unlock()
	results := make([]structs.GoPocsResultType, len(d.results))
	for index, result := range d.results {
		result.Exchanges = append([]structs.GoPocExchange(nil), result.Exchanges...)
		results[index] = result
	}
	return results
}

// DispatchScoped runs GoPoc with task-local services and fingerprints.
func DispatchScoped(ipPortMap map[string]string, fingerprints map[string][]string, goPocThreads int, password string, passwordFile string, nucleiResults []NucleiResult, emit func(structs.OutputMessage)) ([]structs.GoPocsResultType, error) {
	return DispatchWithPresentationScoped(ipPortMap, fingerprints, goPocThreads, password, passwordFile, nucleiResults, emit, Presentation{})
}

// DispatchWithPresentationScoped keeps follow-up triggers within the current
// task. In particular, Agent jobs must never read the legacy global ResultMap.
func DispatchWithPresentationScoped(ipPortMap map[string]string, fingerprints map[string][]string, goPocThreads int, password string, passwordFile string, nucleiResults []NucleiResult, emit func(structs.OutputMessage), presentation Presentation) ([]structs.GoPocsResultType, error) {
	if len(ipPortMap) == 0 && len(nucleiResults) == 0 && len(fingerprints) == 0 {
		return nil, nil
	}

	InitDictionaries()

	if emit == nil {
		emit = func(msg structs.OutputMessage) {
			ddout.FormatOutput(msg)
		}
	}

	dispatcher := &dispatcher{
		emit:         emit,
		presentation: presentation,
	}

	plan := buildDispatchPlan(ipPortMap, fingerprints, nucleiResults, password, passwordFile, dispatcher.writeResult)
	dispatcher.allCount = len(plan)
	if dispatcher.allCount == 0 {
		return nil, nil
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

	wg.Wait()
	if !presentation.MachineOutput {
		fmt.Printf("\r\033[K")
	}
	gologger.Info().Msg("Golang Poc引擎扫描结束")

	results := dispatcher.snapshotResults()
	if len(results) > 0 {
		gologger.Info().Msg("发现漏洞汇总:")
		for _, res := range results {
			gologger.Info().Msgf("[%s] %s %s\n%s", res.Security, res.PocName, res.Target, res.InfoLeft)
		}
	}
	return results, dispatcher.executionError()
}

func appendUniqueScanTask(plan *[]scanTask, seen map[string]struct{}, task scanTask) {
	key := scanTaskIdentity(task)
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	*plan = append(*plan, task)
}

func buildDispatchPlan(ipPortMap map[string]string, fingerprints map[string][]string, nucleiResults []NucleiResult, password, passwordFile string, writeResult func(structs.GoPocsResultType)) []scanTask {
	basePlan := buildScanPlan(ipPortMap, password, passwordFile, writeResult)
	seen := make(map[string]struct{}, len(basePlan)+len(nucleiResults)+len(fingerprints))
	plan := make([]scanTask, 0, len(basePlan)+len(nucleiResults)+len(fingerprints))
	for _, task := range basePlan {
		appendUniqueScanTask(&plan, seen, task)
	}
	for _, result := range nucleiResults {
		if result.TemplateID == "shiro-detect" {
			appendUniqueScanTask(&plan, seen, scanTask{Name: "Shiro-Key-Crack", Info: structs.HostInfo{
				Url: result.Matched, Password: password, PasswordFile: passwordFile,
			}})
		}
		if isViewStateNucleiResult(result) {
			targetURL := firstNonEmpty(result.Matched, result.URL)
			if targetURL != "" {
				appendUniqueScanTask(&plan, seen, scanTask{Name: "ViewState-Key-Crack", Info: structs.HostInfo{
					Url: targetURL, Password: password, PasswordFile: passwordFile,
				}})
			}
		}
	}
	for host, values := range fingerprints {
		for _, fingerprint := range values {
			if strings.EqualFold(fingerprint, "viewstate") {
				appendUniqueScanTask(&plan, seen, scanTask{Name: "ViewState-Key-Crack", Info: structs.HostInfo{
					Url: host, Password: password, PasswordFile: passwordFile,
				}})
			}
		}
	}
	return plan
}

func scanTaskIdentity(task scanTask) string {
	target := strings.TrimSpace(task.Info.Url)
	if parsed, err := url.Parse(target); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		parsed.Scheme = strings.ToLower(parsed.Scheme)
		parsed.Host = strings.ToLower(parsed.Host)
		parsed.Fragment = ""
		if parsed.Path == "" {
			parsed.Path = "/"
		}
		target = parsed.String()
	}
	if target == "" {
		target = strings.ToLower(strings.TrimSpace(task.Info.Host)) + ":" + strings.TrimSpace(task.Info.Ports)
	}
	return task.Name + "\x00" + target
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
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

		// ICS protocols
		if protocol == "dnp3" || port == "20000" {
			tasks = append(tasks, scanTask{Name: "DNP3-Scan", Info: info})
		}
		if protocol == "s7comm" || port == "102" {
			tasks = append(tasks, scanTask{Name: "S7-Scan", Info: info})
		}
		if protocol == "enip" || port == "44818" {
			tasks = append(tasks, scanTask{Name: "EtherNetIP-Scan", Info: info})
		}
		if protocol == "atg" || port == "10001" {
			tasks = append(tasks, scanTask{Name: "ATG-Scan", Info: info})
		}
		if protocol == "melsec" || port == "5006" || port == "5007" {
			tasks = append(tasks, scanTask{Name: "MELSEC-Scan", Info: info})
		}
		if protocol == "fins" || port == "9600" {
			tasks = append(tasks, scanTask{Name: "FINS-Scan", Info: info})
		}
		if protocol == "crimson" || port == "789" {
			tasks = append(tasks, scanTask{Name: "Crimson-Scan", Info: info})
		}
		if protocol == "iec104" || port == "2404" {
			tasks = append(tasks, scanTask{Name: "IEC104-Scan", Info: info})
		}

		// Non-HTTP protocol detection
		if protocol == "ldap" || port == "389" {
			tasks = append(tasks, scanTask{Name: "LDAP-Scan", Info: info})
		}
		if protocol == "zookeeper" || port == "2181" {
			tasks = append(tasks, scanTask{Name: "Zookeeper-Scan", Info: info})
		}
		if protocol == "mqtt" || port == "1883" {
			tasks = append(tasks, scanTask{Name: "MQTT-Scan", Info: info})
		}
		if protocol == "cassandra" || port == "9042" {
			tasks = append(tasks, scanTask{Name: "Cassandra-Scan", Info: info})
		}
		if protocol == "clickhouse" || port == "9000" {
			tasks = append(tasks, scanTask{Name: "ClickHouse-Scan", Info: info})
		}
		if protocol == "activemq" || port == "61616" {
			tasks = append(tasks, scanTask{Name: "ActiveMQ-Scan", Info: info})
		}
		if protocol == "rmi" || port == "1099" {
			tasks = append(tasks, scanTask{Name: "RMI-Scan", Info: info})
		}
		if protocol == "svn" || port == "3690" {
			tasks = append(tasks, scanTask{Name: "SVN-Scan", Info: info})
		}
		if protocol == "hsqldb" || port == "9001" {
			tasks = append(tasks, scanTask{Name: "HsqlDb-Scan", Info: info})
		}
		if protocol == "mysql" && port == "4000" {
			tasks = append(tasks, scanTask{Name: "TiDB-Scan", Info: info})
		}
		if port == "7848" {
			tasks = append(tasks, scanTask{Name: "Nacos-Raft-Scan", Info: info})
		}
		if port == "1801" {
			tasks = append(tasks, scanTask{Name: "MSMQ-Scan", Info: info})
		}
		if port == "50000" {
			tasks = append(tasks, scanTask{Name: "SAP-P4-Scan", Info: info})
		}
		if protocol == "telnet" || port == "23" {
			tasks = append(tasks, scanTask{Name: "Telnet-CVE-Scan", Info: info})
		}
	}
	return tasks
}
