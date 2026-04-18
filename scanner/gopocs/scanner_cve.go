package gopocs

import (
	"dddd/scanner/structs"
	"strings"
	"sync"
)

// TelnetCVEOnlyDispatcher 独立运行 Telnet CVE 扫描，不依赖 NoGolangPoc 开关
func TelnetCVEOnlyDispatcher() {
	structs.GoPocsResults = TelnetBypassDispatch(
		structs.GlobalIPPortMap,
		structs.GlobalConfig.GoPocThreads,
		structs.GlobalConfig.Password,
		structs.GlobalConfig.PasswordFile,
	)
}

func TelnetBypassDispatch(ipPortMap map[string]string, goPocThreads int, password string, passwordFile string) []structs.GoPocsResultType {
	if len(ipPortMap) == 0 {
		return nil
	}

	if goPocThreads <= 0 {
		goPocThreads = 1
	}

	dispatcher := &dispatcher{}
	var ch = make(chan struct{}, goPocThreads)
	var wg = sync.WaitGroup{}

	for hostPort, protocol := range ipPortMap {
		// gologger.Info().Msgf("[Debug] Checking %s protocol: %s", hostPort, protocol)
		t := strings.Split(hostPort, ":")
		if len(t) != 2 {
			continue
		}
		host := t[0]
		port := t[1]

		// 只要是 Telnet 协议 或者 端口是 23
		if protocol == "telnet" || port == "23" {
			dispatcher.addScan("Telnet-Bypass", structs.HostInfo{
				Host:         host,
				Ports:        port,
				Password:     password,
				PasswordFile: passwordFile,
				WriteResult:  dispatcher.writeResult,
			}, ch, &wg)
		}
	}
	wg.Wait()
	return dispatcher.snapshotResults()
}
