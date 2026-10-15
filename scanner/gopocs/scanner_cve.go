package gopocs

import (
	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/structs"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
)

// TelnetBypassDispatchScoped reports dispatcher infrastructure failures to
// task-scoped callers while retaining Telnet probe misses as zero findings.
func TelnetBypassDispatchScoped(ipPortMap map[string]string, goPocThreads int, password string, passwordFile string, emit func(structs.OutputMessage)) ([]structs.GoPocsResultType, error) {
	return TelnetBypassDispatchScopedWithModules(ipPortMap, goPocThreads, password, passwordFile, "", emit)
}

func TelnetBypassDispatchScopedWithModules(ipPortMap map[string]string, goPocThreads int, password string, passwordFile string, modules string, emit func(structs.OutputMessage)) ([]structs.GoPocsResultType, error) {
	if len(ipPortMap) == 0 {
		return nil, nil
	}
	filter, err := newModuleFilter(modules)
	if err != nil {
		return nil, err
	}
	if !filter.allows("Telnet-Bypass") {
		return nil, nil
	}

	if goPocThreads <= 0 {
		goPocThreads = 1
	}

	if emit == nil {
		emit = func(msg structs.OutputMessage) {
			ddout.FormatOutput(msg)
		}
	}

	// 先构建任务列表，以便正确设置 allCount
	var tasks []scanTask
	for hostPort, protocol := range ipPortMap {
		t := strings.Split(hostPort, ":")
		if len(t) != 2 {
			continue
		}
		host := t[0]
		port := t[1]

		if matchObservedOrPort(protocol, port, "telnet", "23") {
			tasks = append(tasks, scanTask{
				Name: "Telnet-Bypass",
				Info: structs.HostInfo{
					Host:         host,
					Ports:        port,
					Password:     password,
					PasswordFile: passwordFile,
				},
			})
		}
	}
	if len(tasks) == 0 {
		return nil, nil
	}

	dispatcher := &dispatcher{
		emit:     emit,
		allCount: len(tasks),
	}

	gologger.Info().Msgf("[TelnetCVE] 启动 Telnet 高危 CVE 专项检测, 目标数: %d", len(tasks))

	var ch = make(chan struct{}, goPocThreads)
	var wg = sync.WaitGroup{}
	for _, task := range tasks {
		task.Info.WriteResult = dispatcher.writeResult
		dispatcher.addScan(task.Name, task.Info, ch, &wg)
	}
	wg.Wait()
	return dispatcher.snapshotResults(), dispatcher.executionError()
}
