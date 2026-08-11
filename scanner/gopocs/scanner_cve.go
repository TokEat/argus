package gopocs

import (
	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/structs"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
)

// TelnetCVEOnlyDispatcher 独立运行 Telnet CVE 扫描，不依赖 NoGolangPoc 开关
func TelnetCVEOnlyDispatcher() {
	structs.GoPocsResults = TelnetBypassDispatch(
		structs.GlobalIPPortMap,
		structs.GlobalConfig.GoPocThreads,
		structs.GlobalConfig.Password,
		structs.GlobalConfig.PasswordFile,
		nil,
	)
}

func TelnetBypassDispatch(ipPortMap map[string]string, goPocThreads int, password string, passwordFile string, emit func(structs.OutputMessage)) []structs.GoPocsResultType {
	if len(ipPortMap) == 0 {
		return nil
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

		if protocol == "telnet" || port == "23" {
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
		return nil
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
	return dispatcher.snapshotResults()
}
