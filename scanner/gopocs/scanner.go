package gopocs

import (
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"sync"

	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/internal/scanner/protocol"
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

	if !d.presentation.MachineOutput && (currentCount%10 == 0 || currentCount == allCount) {
		gologger.Info().Msgf("[GoPoc] 当前进度: %v %v [%v/%v]", name, info.Host+":"+info.Ports, currentCount, allCount)
	}

	ch <- struct{}{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { <-ch }()
		if info.BeforeExecute != nil {
			info.BeforeExecute()
		}
		info.WriteResult = d.writeResult
		info.Emit = d.emit
		if outputType := strings.TrimSpace(info.OutputType); outputType != "" {
			baseEmit := d.emit
			observedService := strings.TrimSpace(info.ObservedService)
			info.Emit = func(message structs.OutputMessage) {
				message.Type = outputType
				if message.Protocol == "" {
					message.Protocol = observedService
				}
				baseEmit(message)
			}
		}
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
	return DispatchWithPresentationAndCreds(ipPortMap, fingerprints, goPocThreads, DispatchCreds{Password: password, PasswordFile: passwordFile}, nucleiResults, emit, Presentation{})
}

func DispatchWithPresentationScoped(ipPortMap map[string]string, fingerprints map[string][]string, goPocThreads int, password string, passwordFile string, nucleiResults []NucleiResult, emit func(structs.OutputMessage), presentation Presentation) ([]structs.GoPocsResultType, error) {
	return DispatchWithPresentationAndCreds(ipPortMap, fingerprints, goPocThreads, DispatchCreds{Password: password, PasswordFile: passwordFile}, nucleiResults, emit, presentation)
}

// DispatchWithPresentationAndCreds keeps follow-up triggers within the current
// task. In particular, Agent jobs must never read the legacy global ResultMap.
func DispatchWithPresentationAndCreds(ipPortMap map[string]string, fingerprints map[string][]string, goPocThreads int, creds DispatchCreds, nucleiResults []NucleiResult, emit func(structs.OutputMessage), presentation Presentation) ([]structs.GoPocsResultType, error) {
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

	plan, err := buildDispatchPlan(ipPortMap, fingerprints, nucleiResults, creds, dispatcher.writeResult)
	if err != nil {
		return nil, err
	}
	dispatcher.allCount = len(plan)
	if dispatcher.allCount == 0 {
		return nil, nil
	}

	if goPocThreads <= 0 {
		goPocThreads = 1
	}

	var ch = make(chan struct{}, goPocThreads)
	var wg = sync.WaitGroup{}
	if !presentation.MachineOutput {
		gologger.Info().Msg("Golang Poc引擎启动")
	}

	for _, task := range plan {
		dispatcher.addScan(task.Name, task.Info, ch, &wg)
	}

	wg.Wait()
	if !presentation.MachineOutput {
		fmt.Printf("\r\033[K")
		gologger.Info().Msg("Golang Poc引擎扫描结束")
	}

	results := dispatcher.snapshotResults()
	if len(results) > 0 {
		gologger.AuditTimeLogger("发现漏洞汇总:")
		for _, res := range results {
			gologger.AuditLogger("[%s] %s %s", res.Security, res.PocName, res.Target)
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

func buildDispatchPlan(ipPortMap map[string]string, fingerprints map[string][]string, nucleiResults []NucleiResult, creds DispatchCreds, writeResult func(structs.GoPocsResultType)) ([]scanTask, error) {
	filter, err := newModuleFilter(creds.Modules)
	if err != nil {
		return nil, err
	}
	basePlan := buildScanPlan(ipPortMap, creds, writeResult)
	seen := make(map[string]struct{}, len(basePlan)+len(nucleiResults)+len(fingerprints))
	plan := make([]scanTask, 0, len(basePlan)+len(nucleiResults)+len(fingerprints))
	for _, task := range basePlan {
		if creds.NoBrute && isServiceBruteTask(task.Name) {
			continue
		}
		if !filter.allows(task.Name) {
			continue
		}
		appendUniqueScanTask(&plan, seen, task)
	}
	for _, result := range nucleiResults {
		if result.TemplateID == "shiro-detect" {
			info := structs.HostInfo{Url: result.Matched}
			applyDispatchCreds(&info, creds)
			appendUniqueAllowedScanTask(&plan, seen, filter, scanTask{Name: "Shiro-Key-Crack", Info: info})
		}
		if isViewStateNucleiResult(result) {
			targetURL := firstNonEmpty(result.Matched, result.URL)
			if targetURL != "" {
				info := structs.HostInfo{Url: targetURL}
				applyDispatchCreds(&info, creds)
				appendUniqueAllowedScanTask(&plan, seen, filter, scanTask{Name: "ViewState-Key-Crack", Info: info})
			}
		}
	}
	for host, values := range fingerprints {
		for _, fingerprint := range values {
			if strings.EqualFold(fingerprint, "viewstate") {
				info := structs.HostInfo{Url: host}
				applyDispatchCreds(&info, creds)
				appendUniqueAllowedScanTask(&plan, seen, filter, scanTask{Name: "ViewState-Key-Crack", Info: info})
			}
		}
	}
	return plan, nil
}

func appendUniqueAllowedScanTask(plan *[]scanTask, seen map[string]struct{}, filter moduleFilter, task scanTask) {
	if !filter.allows(task.Name) {
		return
	}
	appendUniqueScanTask(plan, seen, task)
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

func buildScanPlan(ipPortMap map[string]string, creds DispatchCreds, writeResult func(structs.GoPocsResultType)) []scanTask {
	var tasks []scanTask
	for hostPort, rawProtocol := range ipPortMap {
		t := strings.Split(hostPort, ":")
		if len(t) != 2 {
			continue
		}
		host := t[0]
		port := t[1]
		observed := protocol.CanonicalProtocol(rawProtocol)

		// 减少无效爆破：Web 服务跳过 GoPoc 暴力破解。
		if observed == "http" || observed == "https" {
			continue
		}

		info := structs.HostInfo{
			Host:            host,
			Ports:           port,
			WriteResult:     writeResult,
			ObservedService: observed,
		}
		applyDispatchCreds(&info, creds)

		if matchObservedOrPort(observed, port, "ssh", "22") {
			tasks = append(tasks, scanTask{Name: "SSH-Crack", Info: info})
		}
		if matchObservedOrPort(observed, port, "ftp", "21") {
			tasks = append(tasks, scanTask{Name: "FTP-Crack", Info: info})
		}
		if matchObservedOrPort(observed, port, "mysql", "3306") {
			tasks = append(tasks, scanTask{Name: "Mysql-Crack", Info: info})
		}
		if matchObservedOrPort(observed, port, "mssql", "1433") {
			tasks = append(tasks, scanTask{Name: "Mssql-Crack", Info: info})
		}
		if matchObservedOrPort(observed, port, "oracle", "1521") {
			tasks = append(tasks, scanTask{Name: "Oracle-Crack", Info: info})
		}
		if matchObservedOrPort(observed, port, "mongodb", "27017") {
			tasks = append(tasks, scanTask{Name: "MongoDB-Crack", Info: info})
		}
		if matchObservedOrPort(observed, port, "rdp", "3389") {
			tasks = append(tasks, scanTask{Name: "RDP-Crack", Info: info})
		}
		if matchObservedOrPort(observed, port, "redis", "6379") {
			tasks = append(tasks, scanTask{Name: "Redis-Crack", Info: info})
		}
		if matchObservedOrPort(observed, port, "smb", "445") {
			tasks = append(tasks,
				scanTask{Name: "SMB-MS17-010", Info: info},
				scanTask{Name: "SMB-Crack", Info: info},
			)
		}
		if matchObservedOrPort(observed, port, "postgresql", "5432") {
			tasks = append(tasks, scanTask{Name: "PostgreSQL-Crack", Info: info})
		}
		if matchObservedOrPort(observed, port, "telnet", "23") {
			tasks = append(tasks, scanTask{Name: "Telnet-Crack", Info: info})
		}
		if matchObservedOrPort(observed, port, "memcached", "11211") {
			tasks = append(tasks, scanTask{Name: "Memcache-Crack", Info: info})
		}
		if observed == "netbios" || observed == "smb" || matchObservedOrPort(observed, port, "netbios", "445") {
			tasks = append(tasks, scanTask{Name: "NetBios-GetHostInfo", Info: info})
		}
		if observed == "rpc" {
			tasks = append(tasks, scanTask{Name: "RPC-GetHostInfo", Info: info})
		}
		if observed == "jdwp" {
			tasks = append(tasks, scanTask{Name: "JDWP-Scan", Info: info})
		}
		if matchObservedOrPort(observed, port, "adb", "5555") {
			tasks = append(tasks, scanTask{Name: "ADB-Scan", Info: info})
		}
		if matchObservedOrPort(observed, port, "vnc", "5900", "5901") {
			tasks = append(tasks, scanTask{Name: "VNC-Scan", Info: info})
		}
		if matchObservedOrPort(observed, port, "rsync", "873") {
			tasks = append(tasks, scanTask{Name: "Rsync-Scan", Info: info})
		}
		if matchObservedOrPort(observed, port, "dm", "5236") {
			tasks = append(tasks, scanTask{Name: "DM-Scan", Info: info})
		}
		if matchObservedOrPort(observed, port, "kingbase", "54321") {
			tasks = append(tasks, scanTask{Name: "Kingbase-Scan", Info: info})
		}

		if matchObservedOrPort(observed, port, "ldap", "389") {
			tasks = append(tasks, scanTask{Name: "LDAP-Scan", Info: info})
		}
		if matchObservedOrPort(observed, port, "zookeeper", "2181") {
			tasks = append(tasks, scanTask{Name: "Zookeeper-Scan", Info: info})
		}
		if matchObservedOrPort(observed, port, "mqtt", "1883") {
			tasks = append(tasks, scanTask{Name: "MQTT-Scan", Info: info})
		}
		if matchObservedOrPort(observed, port, "rmi", "1099") {
			tasks = append(tasks, scanTask{Name: "RMI-Scan", Info: info})
		}
		if matchObservedOrPort(observed, port, "telnet", "23") {
			tasks = append(tasks, scanTask{Name: "Telnet-CVE-Scan", Info: info})
		}
		if matchRocketMQRole(observed, port, "10909", "10911") {
			tasks = append(tasks, scanTask{Name: "RocketMQ-Broker-Scan", Info: info})
		}
		if matchRocketMQRole(observed, port, "9876") {
			tasks = append(tasks, scanTask{Name: "RocketMQ-NameServer-Scan", Info: info})
		}
		if matchObservedOrPort(observed, port, "amqp", "5672", "5671") {
			tasks = append(tasks, scanTask{Name: "RabbitMQ-AMQP-Scan", Info: info})
		}
		if matchObservedOrPort(observed, port, "epmd", "4369") {
			tasks = append(tasks, scanTask{Name: "EPMD-Scan", Info: info})
		}
		if matchObservedOrPort(observed, port, "cassandra", "9042") {
			tasks = append(tasks, scanTask{Name: "Cassandra-Scan", Info: info})
		}
		if matchObservedOrPort(observed, port, "clickhouse", "9000") {
			tasks = append(tasks, scanTask{Name: "ClickHouse-Scan", Info: info})
		}
	}
	return tasks
}

func matchRocketMQRole(observed, port string, defaultPorts ...string) bool {
	portMatched := false
	for _, defaultPort := range defaultPorts {
		if port == defaultPort {
			portMatched = true
			break
		}
	}
	if observed == "rocketmq-broker" && containsPort(defaultPorts, "10911") {
		return true
	}
	if observed == "rocketmq-namesrv" && containsPort(defaultPorts, "9876") {
		return true
	}
	if observed == "rocketmq" {
		return portMatched
	}
	if !protocol.Unidentified(observed) {
		return false
	}
	return portMatched
}

func containsPort(ports []string, port string) bool {
	for _, candidate := range ports {
		if candidate == port {
			return true
		}
	}
	return false
}

// matchObservedOrPort dispatches when the identified protocol matches, or when
// the service is still unidentified and the port is a standard fallback.
func matchObservedOrPort(observed, port, wanted string, defaultPorts ...string) bool {
	if observed == wanted {
		return true
	}
	if !protocol.Unidentified(observed) {
		return false
	}
	for _, defaultPort := range defaultPorts {
		if port == defaultPort {
			return true
		}
	}
	return false
}
