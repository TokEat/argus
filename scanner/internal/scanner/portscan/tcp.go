// Package portscan 端口扫描模块。
package portscan

import (
	"bytes"
	"dddd/scanner/ddout"
	"dddd/scanner/lib/masscan"
	"dddd/scanner/utils"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"dddd/scanner/common"

	"github.com/projectdiscovery/gologger"
)

func ScanTCP(ips []string, ports string, timeout int, workers int, portsThreshold int, portScan bool) []string {
	var aliveAddress []string
	gologger.AuditTimeLogger("开始TCP端口扫描，端口设置: %s\nTCP端口扫描目标:%s", ports, strings.Join(ips, ","))

	probePorts := common.ParsePort(ports)
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(probePorts), func(i, j int) {
		probePorts[i], probePorts[j] = probePorts[j], probePorts[i]
	})

	ipPortCount := make(map[string]int)
	backlist := make(map[string]struct{})
	var backlistLock sync.Mutex

	if workers > len(ips)*len(probePorts) {
		workers = len(ips) * len(probePorts)
	}
	if workers <= 0 {
		workers = 1
	}

	addrs := make(chan addr, len(ips)*len(probePorts))
	results := make(chan string, len(ips)*len(probePorts))
	var wg sync.WaitGroup

	go func() {
		for found := range results {
			aliveAddress = append(aliveAddress, found)

			parts := strings.Split(found, ":")
			ip := parts[0]
			count := ipPortCount[ip]
			if count > portsThreshold {
				backlistLock.Lock()
				if _, exists := backlist[ip]; !exists {
					backlist[ip] = struct{}{}
					gologger.Error().Msgf("%s 端口数量超出阈值,放弃扫描", ip)
				}
				backlistLock.Unlock()
			}
			ipPortCount[ip] = count + 1
			wg.Done()
		}
	}()

	for i := 0; i < workers; i++ {
		go func() {
			for item := range addrs {
				portConnect(item, results, timeout, portScan, portsThreshold, &backlist, &backlistLock, &wg)
				wg.Done()
			}
		}()
	}

	for _, port := range probePorts {
		for _, host := range ips {
			wg.Add(1)
			addrs <- addr{ip: host, port: port}
		}
	}

	wg.Wait()
	close(addrs)
	close(results)
	gologger.AuditTimeLogger("TCP端口扫描结束")
	return aliveAddress
}

type addr struct {
	ip   string
	port int
}

func portConnect(item addr, respondingHosts chan<- string, adjustedTimeout int, portScan bool, portsThreshold int, backlist *map[string]struct{}, backlistLock *sync.Mutex, wg *sync.WaitGroup) {
	backlistLock.Lock()
	_, blocked := (*backlist)[item.ip]
	backlistLock.Unlock()
	if blocked {
		return
	}

	conn, err := common.WrapperTcpWithTimeout("tcp4", fmt.Sprintf("%s:%d", item.ip, item.port), time.Duration(adjustedTimeout)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return
	}

	if portScan {
		ddout.FormatOutput(ddout.OutputMessage{
			Type: "PortScan",
			IP:   item.ip,
			Port: strconv.Itoa(item.port),
		})
	} else {
		ddout.FormatOutput(ddout.OutputMessage{
			Type:          "IPAlive",
			IP:            item.ip,
			AdditionalMsg: "TCP:" + strconv.Itoa(item.port),
		})
	}
	wg.Add(1)
	respondingHosts <- item.ip + ":" + strconv.Itoa(item.port)
}

func ScanSYN(ips []string, masscanPath string, synThreads int) []string {
	ipsPayload := strings.Join(utils.RemoveDuplicateElement(ips), "\n")
	if err := os.WriteFile("masscan_tmp.txt", []byte(ipsPayload), 0o666); err != nil {
		return []string{}
	}
	defer os.Remove("masscan_tmp.txt")

	ms := masscan.New(masscanPath)
	ms.SetFileName("masscan_tmp.txt")
	ms.SetPorts("1-65535")
	ms.SetRate(strconv.Itoa(synThreads))
	gologger.Info().Msgf("调用masscan进行SYN端口扫描")
	if err := ms.Run(); err != nil {
		return []string{}
	}
	gologger.AuditTimeLogger("masscan扫描结束")

	hosts, err := ms.Parse()
	if err != nil {
		gologger.Error().Msgf("masscan结果解析失败")
		return []string{}
	}

	var results []string
	for _, each := range hosts {
		for _, port := range each.Ports {
			results = append(results, each.Address.Addr+":"+port.Portid)
		}
	}

	results = utils.RemoveDuplicateElement(results)
	for _, each := range results {
		parts := strings.Split(each, ":")
		if len(parts) != 2 {
			continue
		}
		ddout.FormatOutput(ddout.OutputMessage{
			Type: "PortScan",
			IP:   parts[0],
			Port: parts[1],
		})
	}
	return results
}

func CheckMasscan(masscanPath string) bool {
	bsenv := ""
	if runtime.GOOS != "windows" {
		bsenv = "/bin/bash"
	}

	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("cmd", "/c", masscanPath)
	default:
		command = exec.Command(bsenv, "-c", masscanPath)
	}

	outinfo := bytes.Buffer{}
	command.Stdout = &outinfo
	if err := command.Start(); err != nil {
		gologger.Error().Msgf("未检测到路径 %v 存在masscan", masscanPath)
		return false
	}
	_ = command.Wait()

	if !strings.Contains(outinfo.String(), "masscan -p80,8000-8100 10.0.0.0/8 --rate=10000") {
		gologger.Error().Msgf("未检测到路径 %v 存在masscan", masscanPath)
		return false
	}
	return true
}

func RemoveFirewall(ipPorts []string, portsThreshold int) []string {
	var results []string
	gologger.AuditTimeLogger("移除开放端口过多的目标")

	grouped := make(map[string][]string)
	for _, ipPort := range ipPorts {
		parts := strings.Split(ipPort, ":")
		if len(parts) != 2 {
			continue
		}
		grouped[parts[0]] = append(grouped[parts[0]], parts[1])
	}

	for ip, ports := range grouped {
		uniquePorts := utils.RemoveDuplicateElement(ports)
		if len(uniquePorts) >= portsThreshold {
			gologger.Error().Msgf("%s 端口数量超出阈值,已丢弃", ip)
			continue
		}
		for _, port := range uniquePorts {
			results = append(results, ip+":"+port)
		}
	}
	return utils.RemoveDuplicateElement(results)
}
