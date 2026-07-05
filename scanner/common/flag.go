package common

import (
	"dddd/scanner/ddout"
	"dddd/scanner/lib/ddfinger"
	"dddd/scanner/structs"
	"dddd/scanner/utils"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/retryablehttp-go"
	"gopkg.in/yaml.v3"
)

func init() {
	go func() {
		for {
			GC()
			time.Sleep(10 * time.Second)
		}
	}()
}

func GC() {
	runtime.GC()
	debug.FreeOSMemory()
}

var version = "2.0.1"

func showBanner() {
	banner := fmt.Sprintf(`
     _       _       _       _   
  __| |   __| |   __| |   __| |  
 / _`+"`"+` |  / _ `+"`"+`|  / _`+"`"+` |  / _`+"`"+` |  
 \__,_|  \__,_|  \__,_|  \__,_|  
_|"""""|_|"""""|_|"""""|_|"""""| 
"`+"`"+`-0-0-'"`+"`"+`-0-0-'"`+"`"+`-0-0-`+"`"+`"`+"`"+`-0-0-'
dddd.version: %s
`, version)
	fmt.Println(banner)
}

var TargetString string
var PortString string
var disableWAFBypassHeaders bool
var disableWAFSkipOnManyFingerprints bool

//go:embed config/dir.yaml
var EmbedDirDBData string

//go:embed config/finger.yaml
var EmbedFingerData string

//go:embed config/api-config.yaml
var EmbedAPIConfigData string

// EmbedNucleiPocs 由 embed_pocs.go (默认内嵌) 或 embed_nopocs.go (noembed tag) 提供。
// Agent 模式构建时使用 -tags noembed 可跳过内嵌 POC，减小二进制体积。

func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func splitPathAndFileName(path string) (string, string) {
	p := strings.ReplaceAll(path, "\\", "/")
	if !strings.Contains(path, "/") {
		return "", p
	}
	t := strings.Split(p, "/")
	return strings.Join(t[:len(t)-1], "/"), t[len(t)-1]
}

func ReadDirDB() {
	// 先读取默认的，再读取文件内的进行补充
	fps := make(map[string]interface{})
	err := yaml.Unmarshal([]byte(EmbedDirDBData), &fps)
	if err != nil {
		return
	}

	structs.DirDB = make(map[string][]string)
	for productName, pathsInterfaces := range fps {
		for _, pathsInterface := range pathsInterfaces.([]interface{}) {
			p := pathsInterface.(string)
			_, ok := structs.DirDB[p]
			if ok {
				structs.DirDB[p] = append(structs.DirDB[p], productName)
				structs.DirDB[p] = utils.RemoveDuplicateElement(structs.DirDB[p])
			} else {
				structs.DirDB[p] = []string{productName}
			}
		}
	}

	var data []byte
	if !fileExists(structs.GlobalConfig.DirSearchYaml) {
		return
	}
	data, err = os.ReadFile(structs.GlobalConfig.DirSearchYaml)
	if err != nil {
		return
	}

	fps = make(map[string]interface{})
	err = yaml.Unmarshal(data, &fps)
	if err != nil {
		return
	}
	for productName, pathsInterfaces := range fps {
		for _, pathsInterface := range pathsInterfaces.([]interface{}) {
			p := pathsInterface.(string)
			_, ok := structs.DirDB[p]
			if ok {
				structs.DirDB[p] = append(structs.DirDB[p], productName)
				structs.DirDB[p] = utils.RemoveDuplicateElement(structs.DirDB[p])
			} else {
				structs.DirDB[p] = []string{productName}
			}
		}
	}

}

func IsLinux() bool {
	os := runtime.GOOS
	if os == "linux" {
		return true
	}
	return false
}

//go:embed config/workflow.yaml
var EmbedWorkFlowData string

func ReadWorkFlowDB() {
	structs.WorkFlowDB = make(map[string]structs.WorkFlowEntity)
	fps := make(map[string]interface{})
	err := yaml.Unmarshal([]byte(EmbedWorkFlowData), &fps)
	if err == nil {
		for productName, rulesInterface := range fps {
			var workflowEntity structs.WorkFlowEntity
			ruleInterface := rulesInterface.(map[string]interface{})
			types := ruleInterface["type"]
			pocs := ruleInterface["pocs"]
			for _, v := range types.([]interface{}) {
				vString := v.(string)
				if strings.ToLower(vString) == "root" {
					workflowEntity.RootType = true
				} else if strings.ToLower(vString) == "dir" {
					workflowEntity.DirType = true
				} else if strings.ToLower(vString) == "base" {
					workflowEntity.BaseType = true
				} else if strings.ToLower(vString) == "dir-fallback" {
					workflowEntity.DirFallback = true
				}
			}
			for _, v := range pocs.([]interface{}) {
				vString := v.(string)
				workflowEntity.PocsName = append(workflowEntity.PocsName, vString)
			}
			workflowEntity.PocsName = utils.RemoveDuplicateElement(workflowEntity.PocsName)
			structs.WorkFlowDB[productName] = workflowEntity
		}
	}

	workflowPath := structs.GlobalConfig.WorkflowYamlPath

	var data []byte
	if !fileExists(workflowPath) {
		return
	}
	data, err = os.ReadFile(workflowPath)
	if err != nil {
		return
	}
	fps = make(map[string]interface{})
	err = yaml.Unmarshal(data, &fps)
	if err != nil {
		return
	}

	for productName, rulesInterface := range fps {
		_, ok := structs.WorkFlowDB[productName]
		if ok {
			we, _ := structs.WorkFlowDB[productName]
			ruleInterface := rulesInterface.(map[string]interface{})
			types := ruleInterface["type"]
			pocs := ruleInterface["pocs"]
			for _, v := range types.([]interface{}) {
				vString := v.(string)
				if strings.ToLower(vString) == "root" {
					we.RootType = true
				} else if strings.ToLower(vString) == "dir" {
					we.DirType = true
				} else if strings.ToLower(vString) == "base" {
					we.BaseType = true
				} else if strings.ToLower(vString) == "dir-fallback" {
					we.DirFallback = true
				}
			}
			for _, v := range pocs.([]interface{}) {
				vString := v.(string)
				if utils.GetItemInArray(we.PocsName, vString) == -1 {
					we.PocsName = append(we.PocsName, vString)
				}
			}
			structs.WorkFlowDB[productName] = we
		} else {
			var workflowEntity structs.WorkFlowEntity
			ruleInterface := rulesInterface.(map[string]interface{})
			types := ruleInterface["type"]
			pocs := ruleInterface["pocs"]
			for _, v := range types.([]interface{}) {
				vString := v.(string)
				if strings.ToLower(vString) == "root" {
					workflowEntity.RootType = true
				} else if strings.ToLower(vString) == "dir" {
					workflowEntity.DirType = true
				} else if strings.ToLower(vString) == "base" {
					workflowEntity.BaseType = true
				} else if strings.ToLower(vString) == "dir-fallback" {
					workflowEntity.DirFallback = true
				}
			}
			for _, v := range pocs.([]interface{}) {
				vString := v.(string)
				workflowEntity.PocsName = append(workflowEntity.PocsName, vString)
			}
			workflowEntity.PocsName = utils.RemoveDuplicateElement(workflowEntity.PocsName)
			structs.WorkFlowDB[productName] = workflowEntity
		}
	}
}

func ToInt(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return i
}

func GetFdLimit() int {
	cmd := exec.Command("sh", "-c", "ulimit -n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		println(err.Error())
		return -1
	}
	s := strings.TrimSpace(string(out))
	return ToInt(s)
}

func prepare() {
	var tmpTargets []string

	// 参数冲突校验
	if structs.GlobalConfig.ReportName != "" {
		suffix := path.Ext(structs.GlobalConfig.ReportName)
		if suffix != ".html" && suffix != ".htm" {
			gologger.Fatal().Msgf("输出参数(-o)必须为html拓展名或htm拓展名")
		}
	}
	if (structs.GlobalConfig.Fofa || structs.GlobalConfig.Hunter) && structs.GlobalConfig.Quake {
		structs.GlobalConfig.Fofa = false
		structs.GlobalConfig.Quake = false
		gologger.Warning().Msg("quake参数不兼容fofa或hunter参数")
	}

	if !strings.HasSuffix(strings.ToLower(structs.GlobalConfig.APIConfigFilePath), ".yaml") {
		gologger.Fatal().Msg("API配置文件需要以 .yaml 为拓展名。")
	}

	structs.GlobalEmbedPocs = EmbedNucleiPocs

	// 进行需要配置API的活动，没有找到API配置文件则直接进行生成
	if structs.GlobalConfig.Fofa || structs.GlobalConfig.Hunter || structs.GlobalConfig.Quake || (structs.GlobalConfig.Subdomain && !structs.GlobalConfig.NoSubFinder) {
		if !fileExists(structs.GlobalConfig.APIConfigFilePath) && !fileExists("config/api-config.yaml") {
			gologger.Info().Msgf("未检测到API配置文件: %v", structs.GlobalConfig.APIConfigFilePath)
			p, _ := splitPathAndFileName(structs.GlobalConfig.APIConfigFilePath)
			if !fileExists(p) {
				err := os.MkdirAll(p, os.ModePerm)
				if err != nil {
					gologger.Fatal().Msgf("创建文件夹失败: %v", err.Error())
				}
			}

			err := os.WriteFile(structs.GlobalConfig.APIConfigFilePath, []byte(EmbedAPIConfigData), 0666)
			if err != nil {
				gologger.Fatal().Msgf("写出默认API配置文件失败: %v", err.Error())
			}
			gologger.Info().Msgf("已自动生成默认API配置文件: %v", structs.GlobalConfig.APIConfigFilePath)
		}
	}

	if !structs.GlobalConfig.SkipHostDiscovery && !structs.GlobalConfig.TCPPing && structs.GlobalConfig.NoICMPPing {
		gologger.Warning().Msg("未选择TCP或ICMP Ping，跳过存活探测")
		structs.GlobalConfig.SkipHostDiscovery = true
	}

	if structs.GlobalConfig.HTTPProxyTest && structs.GlobalConfig.HTTPProxy != "" {
		proxyURL, parseErr := url.Parse(structs.GlobalConfig.HTTPProxy)
		if parseErr != nil {
			gologger.Fatal().Msgf("代理格式不正确: %v", structs.GlobalConfig.HTTPProxy)
		}
		transport := retryablehttp.DefaultHostSprayingTransport()
		transport.Proxy = http.ProxyURL(proxyURL)

		gologger.Info().Msgf("测试代理中: %s", structs.GlobalConfig.HTTPProxy)
		req, err := retryablehttp.NewRequest("GET", structs.GlobalConfig.HTTPProxyTestURL, nil)
		if err != nil {
			gologger.Fatal().Msg("代理测试失败！")
		}
		opts := retryablehttp.DefaultOptionsSpraying
		client := retryablehttp.NewClient(opts)
		client.HTTPClient.Transport = transport

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36")
		resp, err := client.Do(req)
		if err != nil {
			gologger.Fatal().Msg("代理测试失败！")
		}
		gologger.Info().Msgf("代理有效！测试URL返回码: %v", resp.StatusCode)
	}

	// 兼容文件输入
	if utils.IsFileNameValid(TargetString) {
		fileBytes, err := os.ReadFile(TargetString)
		if err == nil && len(fileBytes) > 0 {
			// 兼容Windows输入
			content := strings.ReplaceAll(string(fileBytes), "\r\n", "\n")
			tmpTargets = strings.Split(content, "\n")
		}
	} else {
		tgs := strings.Split(TargetString, ",")
		for _, each := range tgs {
			if each != "" {
				tmpTargets = append(tmpTargets, each)
			}
		}
	}
	tmpTargets = utils.RemoveDuplicateElement(tmpTargets)

	// 低感知模式
	if structs.GlobalConfig.LowPerceptionMode {
		if structs.GlobalConfig.Fofa && structs.GlobalConfig.Hunter {
			gologger.Fatal().Msg("暂不支持在低感知模式下同时使用-fofa与-hunter参数，请使用-hunter参数")
		}
		if structs.GlobalConfig.Fofa {
			gologger.Fatal().Msg("暂不支持基于Fofa的低感知模式，请使用-hunter参数。")
		}
		// 默认使用hunter fofa不支持
		if !structs.GlobalConfig.Fofa && !structs.GlobalConfig.Hunter {
			structs.GlobalConfig.Hunter = true
		}
		// 低感知模式下不进行目录探测
		structs.GlobalConfig.NoDirSearch = true
	}

	structs.GlobalResultMap = make(map[string][]string)
	structs.DirFallbackResultMap = make(map[string][]string)

	// 过滤不支持输入
	for _, tg := range tmpTargets {
		if tg == "" {
			continue
		}
		if structs.GlobalConfig.Hunter || structs.GlobalConfig.Fofa {
			// 从网络空间搜索引擎中获取目标
			if !strings.Contains(tg, "=") {
				gologger.Error().Msgf("不支持的格式: %s", tg)
				continue
			}
		} else if structs.GlobalConfig.Quake {
			if !strings.Contains(tg, ":") {
				gologger.Error().Msgf("不支持的格式: %s", tg)
				continue
			}
		} else if !structs.GlobalConfig.Fofa && !structs.GlobalConfig.Hunter {
			// 从本地文件获取目标
			if utils.GetInputType(tg) == structs.TypeUnSupport {
				if strings.HasPrefix(tg, "[") {
					// 解析历史指纹
					if strings.HasPrefix(tg, "[Finger") {
						t := strings.Split(tg, " ")
						uri := t[1]
						tf := ""

						if strings.HasPrefix(uri, "http") {
							tf = t[3]
						} else {
							tf = t[2]
						}
						if len(tf) <= 2 {
							continue
						}
						tf = tf[1 : len(tf)-1]
						fingers := strings.Split(tf, ",")
						structs.GlobalResultMap[uri] = fingers
						continue
					}

				} else if strings.HasPrefix(tg, "{") {
					var in ddout.OutputMessage
					err := json.Unmarshal([]byte(tg), &in)
					if err == nil {
						if in.Type == "Finger" {
							structs.GlobalResultMap[in.URI] = in.Finger
							continue
						}
						continue
					}

				} else if strings.HasSuffix(tg, " open") {
					ipPort := strings.ReplaceAll(tg, " open", "")
					if utils.IsIPPort(ipPort) {
						structs.GlobalConfig.Targets = append(structs.GlobalConfig.Targets, ipPort)
						continue
					}

				}
				// gologger.Error().Msgf("不支持的格式: %s", tg)
				continue
			}
		}

		structs.GlobalConfig.Targets = append(structs.GlobalConfig.Targets, tg)
	}

	if len(structs.GlobalConfig.Targets) == 0 && len(structs.GlobalResultMap) == 0 {
		gologger.Fatal().Msgf("无目标输入")
	}

	loc := time.FixedZone("CST", 8*3600)
	timestamp := time.Now().In(loc).Format("20060102_150405")
	taskName := "task"
	if utils.IsFileNameValid(TargetString) && fileExists(TargetString) {
		taskName = filepath.Base(TargetString)
	} else if len(structs.GlobalConfig.Targets) > 0 {
		taskName = structs.GlobalConfig.Targets[0]
	} else if structs.GlobalConfig.ReportName != "" {
		taskName = strings.TrimSuffix(filepath.Base(structs.GlobalConfig.ReportName), filepath.Ext(structs.GlobalConfig.ReportName))
	}

	taskName = strings.ReplaceAll(taskName, "://", "_")
	taskName = strings.ReplaceAll(taskName, "/", "_")
	taskName = strings.ReplaceAll(taskName, ":", "_")
	taskName = strings.ReplaceAll(taskName, "\\", "_")
	if len(taskName) > 50 {
		taskName = taskName[:50]
	}
	taskName = strings.Trim(taskName, "._")

	dirName := filepath.Join("datas", fmt.Sprintf("%s_%s", taskName, timestamp))
	if err := os.MkdirAll(dirName, 0755); err == nil {
		gologger.Info().Msgf("结果目录: %s", dirName)
		structs.GlobalConfig.OutputFile = filepath.Join(dirName, filepath.Base(structs.GlobalConfig.OutputFile))

		if structs.GlobalConfig.ReportName != "" {
			structs.GlobalConfig.ReportName = filepath.Join(dirName, filepath.Base(structs.GlobalConfig.ReportName))
		} else {
			structs.GlobalConfig.ReportName = filepath.Join(dirName, timestamp+".html")
		}

		if gologger.AuditLogFileName != "" {
			gologger.AuditLogFileName = filepath.Join(dirName, filepath.Base(gologger.AuditLogFileName))
		}
	} else {
		gologger.Warning().Msgf("创建结果目录失败: %v", err)
	}

	// 如果是Linux则调整扫描线程 gogo抄的感谢感谢
	if IsLinux() {
		structs.GlobalConfig.TCPPortScanThreads = 4000
		if fdlimit := GetFdLimit(); structs.GlobalConfig.TCPPortScanThreads > fdlimit {
			gologger.Warning().Msgf("System fd limit: %d , Please exec 'ulimit -n 65535'", fdlimit)
			gologger.Warning().Msgf("Now set threads to %d", fdlimit-100)
			structs.GlobalConfig.TCPPortScanThreads = fdlimit - 100
		}
	}

	ddout.OutputType = structs.GlobalConfig.OutputType
	ddout.OutputFileName = structs.GlobalConfig.OutputFile

	if PortString == "" {
		// 默认端口Top1000
		structs.GlobalConfig.Ports = PortTOP100
	} else {
		structs.GlobalConfig.Ports = PortString
	}

	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		gologger.Fatal().Msg("Web响应体缓存数据库初始化失败。")
	}
	structs.GlobalHttpBodyHMap = hm

	hm, err = hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		gologger.Fatal().Msg("Web响应头缓存数据库初始化失败。")
	}
	structs.GlobalHttpHeaderHMap = hm

	hm, err = hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		gologger.Fatal().Msg("Banner缓存数据库初始化失败。")
	}
	structs.GlobalBannerHMap = hm
	structs.GlobalIPPortMap = make(map[string]string)
	structs.GlobalIPDomainMap = make(map[string][]string)
	structs.GlobalURLMap = make(map[string]structs.URLEntity)

	parseFingerDB()
	if len(structs.FingerprintDB) == 0 {
		gologger.Fatal().Msg("请检查指纹数据库是否正常，是否正确放置config文件夹。")
	}
	gologger.Info().Msgf("YAML指纹数据: %d 条\n", len(structs.FingerprintDB))

	ReadWorkFlowDB()
	if len(structs.WorkFlowDB) == 0 {
		gologger.Fatal().Msg("请检查工作流数据库是否正常。")
	}
	gologger.Info().Msgf("漏洞检测支持指纹: %d 条", len(structs.WorkFlowDB))

	ReadDirDB()
	if len(structs.DirDB) == 0 {
		gologger.Fatal().Msg("请检查主动指纹探测数据库是否正常。")
	}
}

func parseFingerDB() {
	fps := make(map[string]interface{})
	err := yaml.Unmarshal([]byte(EmbedFingerData), &fps)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	m := make(map[string][]string)

	for productName, rulesInterface := range fps {
		for _, ruleInterface := range rulesInterface.([]interface{}) {
			ruleL := ruleInterface.(string)
			_, ok := m[productName]
			if ok {
				f, _ := m[productName]
				if utils.GetItemInArray(f, ruleL) == -1 {
					f = append(f, ruleL)
				}
				m[productName] = f
			} else {
				m[productName] = []string{ruleL}
			}
		}
	}

	fingerPath := structs.GlobalConfig.FingerConfigFilePath

	if fileExists(fingerPath) {
		data, err := os.ReadFile(fingerPath)
		fps = make(map[string]interface{})
		err = yaml.Unmarshal(data, &fps)
		if err == nil {
			for productName, rulesInterface := range fps {
				for _, ruleInterface := range rulesInterface.([]interface{}) {
					ruleL := ruleInterface.(string)
					_, ok := m[productName]
					if ok {
						f, _ := m[productName]
						if utils.GetItemInArray(f, ruleL) == -1 {
							f = append(f, ruleL)
						}
						m[productName] = f
					} else {
						m[productName] = []string{ruleL}
					}
				}
			}
		}
	}

	for productName, ruleLs := range m {
		for _, ruleL := range ruleLs {
			func() {
				defer func() {
					if r := recover(); r != nil {
						gologger.Error().Msgf("[Finger] ParseRule panic for %s: %v — skipping rule", productName, r)
					}
				}()
				structs.FingerprintDB = append(structs.FingerprintDB, structs.FingerPEntity{ProductName: productName, Rule: ddfinger.ParseRule(ruleL), AllString: ruleL})
			}()
		}
	}

}

func Flag() {
	showBanner()

	flagSet := goflags.NewFlagSet()
	flagSet.CaseSensitive = true
	flagSet.SetDescription(`dddd是一款使用简单的批量信息收集,供应链漏洞探测工具。旨在优化红队工作流，减少伤肝、枯燥、乏味的机械性操作。`)
	flagSet.SetCustomHelpText(`
子命令:
  finger      管理指纹规则库
  poc         管理 POC 规则库
  workflow    管理指纹到 POC 的映射关系

帮助:
  dddd help
  dddd help finger
  dddd help poc
  dddd help workflow
  dddd finger --help
  dddd poc --help
  dddd workflow --help

示例:
  dddd -t https://example.com
  dddd finger list --product nginx
  dddd poc list --severity high
  dddd workflow list --product ruoyi`)

	// 目标设置
	flagSet.CreateGroup("input", "扫描目标",
		flagSet.StringVarP(&TargetString, "target", "t", "", "被扫描的目标。 192.168.0.1 192.168.0.0/16 192.168.0.1:80 baidu.com:80 file.txt(一行一个) result.txt(fscan/dddd)"),
	)

	flagSet.CreateGroup("portscan", "端口扫描",
		flagSet.StringVarP(&PortString, "port", "p", "", "端口设置。 默认扫描Top1000"),
		flagSet.StringVarP(&structs.GlobalConfig.PortScanType, "scan-type", "st", "tcp", "端口扫描方式 | \"-st tcp\"设置TCP扫描 | \"-st syn\"设置SYN扫描"),
		flagSet.IntVarP(&structs.GlobalConfig.TCPPortScanThreads, "tcp-scan-threads", "tst", 1000, "TCP扫描线程 | Windows/Mac默认1000线程 Linux默认4000"),
		flagSet.IntVarP(&structs.GlobalConfig.SYNPortScanThreads, "syn-scan-threads", "sst", 10000, "SYN扫描线程"),
		flagSet.StringVarP(&structs.GlobalConfig.MasscanPath, "masscan-path", "mp", "masscan", "指定masscan程序路径 | SYN扫描依赖"),
		flagSet.IntVarP(&structs.GlobalConfig.PortsThreshold, "ports-max-count", "pmc", 300, "IP端口数量阈值 | 当一个IP的端口数量超过此值，此IP将会被抛弃"),
		flagSet.IntVarP(&structs.GlobalConfig.TCPPortScanTimeout, "port-scan-timeout", "pst", 6, "TCP端口扫描超时(秒)"),
	)

	flagSet.CreateGroup("alive", "主机发现",
		flagSet.BoolVar(&structs.GlobalConfig.SkipHostDiscovery, "Pn", false, "禁用主机发现功能(icmp,tcp)"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoICMPPing, "no-icmp-ping", "nip", false, "当启用主机发现功能时，禁用ICMP主机发现功能"),
		flagSet.BoolVarP(&structs.GlobalConfig.TCPPing, "tcp-ping", "tp", false, "当启用主机发现功能时，启用TCP主机发现功能"),
	)

	flagSet.CreateGroup("nmap", "协议识别",
		flagSet.IntVarP(&structs.GlobalConfig.GetBannerThreads, "nmap-threads", "tc", 500, "Nmap协议识别线程"),
		flagSet.IntVarP(&structs.GlobalConfig.GetBannerTimeout, "nmap-timeout", "nto", 5, "Nmap协议识别超时时间(秒)"),
	)

	flagSet.CreateGroup("subdomain", "探索子域名",
		flagSet.BoolVarP(&structs.GlobalConfig.Subdomain, "subdomain", "sd", false, "开启子域名枚举，默认关闭"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoSubdomainBruteForce, "no-subdomain-brute", "nsb", false, "关闭子域名爆破"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoSubFinder, "no-subfinder", "ns", false, "关闭被动子域名枚举"),
		flagSet.IntVarP(&structs.GlobalConfig.SubdomainBruteForceThreads, "subdomain-brute-threads", "sbt", 150, "子域名爆破线程数量"),
		flagSet.BoolVarP(&structs.GlobalConfig.AllowLocalAreaDomain, "local-domain", "ld", false, "允许域名解析到局域网"),
		flagSet.BoolVarP(&structs.GlobalConfig.AllowCDNAssets, "allow-cdn", "ac", false, "允许扫描带CDN的资产 | 默认略过"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoHostBind, "no-host-bind", "nhb", false, "禁用域名绑定资产探测"),
	)

	flagSet.CreateGroup("web", "Web探针配置",
		flagSet.IntVarP(&structs.GlobalConfig.WebThreads, "web-threads", "wt", 200, "Web探针线程,根据网络环境调整"),
		flagSet.IntVarP(&structs.GlobalConfig.WebTimeout, "web-timeout", "wto", 10, "Web探针超时时间,根据网络环境调整"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoDirSearch, "no-dir", "nd", false, "关闭主动Web指纹探测"),
	)

	flagSet.CreateGroup("proxy", "HTTP代理配置",
		flagSet.StringVarP(&structs.GlobalConfig.HTTPProxy, "proxy", "", "", "HTTP代理"),
		flagSet.BoolVarP(&structs.GlobalConfig.HTTPProxyTest, "proxy-test", "pt", true, "启动前测试HTTP代理"),
		flagSet.StringVarP(&structs.GlobalConfig.HTTPProxyTestURL, "proxy-test-url", "ptu", "https://www.baidu.com", "测试HTTP代理的url，需要url返回200"),
	)

	flagSet.CreateGroup("uncover", "网络空间搜索引擎",
		flagSet.BoolVar(&structs.GlobalConfig.Hunter, "hunter", false, "从hunter中获取资产,开启此选项后-t参数变更为需要在hunter中搜索的关键词"),
		flagSet.IntVarP(&structs.GlobalConfig.HunterPageSize, "hunter-page-size", "hps", 100, "Hunter查询每页资产条数"),
		flagSet.IntVarP(&structs.GlobalConfig.HunterMaxPageCount, "hunter-max-page-count", "hmpc", 10, "Hunter 最大查询页数"),
		flagSet.BoolVarP(&structs.GlobalConfig.LowPerceptionMode, "low-perception-mode", "lpm", false, "Hunter低感知模式 | 从Hunter直接取响应判断指纹，直接进入漏洞扫描阶段"),
		flagSet.BoolVar(&structs.GlobalConfig.OnlyIPPort, "oip", false, "从网络空间搜索引擎中以IP:Port的形式拉取资产，而不是Domain(IP):Port"),
		flagSet.BoolVar(&structs.GlobalConfig.Fofa, "fofa", false, "从Fofa中获取资产,开启此选项后-t参数变更为需要在fofa中搜索的关键词"),
		flagSet.IntVarP(&structs.GlobalConfig.FofaMaxCount, "fofa-max-count", "fmc", 100, "Fofa 查询资产条数 Max:10000"),
		flagSet.BoolVar(&structs.GlobalConfig.Quake, "quake", false, "从Quake中获取资产,开启此选项后-t参数变更为需要在quake中搜索的关键词"),
		flagSet.IntVarP(&structs.GlobalConfig.QuakeSize, "quake-max-count", "qmc", 100, "Quake 查询资产条数"),
	)

	flagSet.CreateGroup("output", "输出",
		flagSet.StringVarP(&structs.GlobalConfig.OutputFile, "output", "o", "result.txt", "结果输出文件"),
		flagSet.StringVarP(&structs.GlobalConfig.OutputType, "output-type", "ot", "text", "结果输出格式 text,json"),
		flagSet.StringVarP(&structs.GlobalConfig.ReportName, "html-output", "ho", "", "html漏洞报告的名称"),
	)

	flagSet.CreateGroup("vuln-detect", "漏洞探测",
		flagSet.BoolVar(&structs.GlobalConfig.NoPoc, "npoc", false, "关闭漏洞探测,只进行信息收集"),
		flagSet.StringVarP(&structs.GlobalConfig.PocNameForSearch, "poc-name", "poc", "", "模糊匹配Poc名称"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoInteractsh, "no-interactsh", "ni", true, "禁用Interactsh服务器，排除反连模版"),
		flagSet.IntVarP(&structs.GlobalConfig.GoPocThreads, "golang-poc-threads", "gpt", 50, "GoPoc运行线程"),
		flagSet.BoolVarP(&structs.GlobalConfig.GolangPoc, "golang-poc", "gp", false, "开启弱口令/Golang Poc探测"),
		flagSet.BoolVarP(&structs.GlobalConfig.DisableGeneralPoc, "disable-general-poc", "dgp", false, "禁用无视指纹的漏洞映射"),
		flagSet.BoolVar(&structs.GlobalConfig.WAFBypassHeaders, "waf-bypass-headers", true, "启用WAF绕过请求头，默认开启"),
		flagSet.BoolVar(&disableWAFBypassHeaders, "no-waf-bypass-headers", false, "关闭默认WAF绕过请求头"),
		flagSet.BoolVar(&disableWAFSkipOnManyFingerprints, "no-waf-skip-many-fingerprints", false, "关闭多指纹目标跳过POC映射，默认开启"),
		flagSet.StringVarP(&structs.GlobalConfig.ExcludeTags, "exclude-tags", "et", "", "通过tags排除模版 | 多个tags请用,连接"),
		flagSet.StringVarP(&structs.GlobalConfig.Severities, "severity", "s", "", "只允许指定严重程度的模板运行 | 多参数用,连接 | 允许的值: "+strings.ReplaceAll(severity.GetSupportedSeverities().String(), " ", "")),
	)

	flagSet.CreateGroup("config", "配置文件",
		flagSet.StringVarP(&structs.GlobalConfig.APIConfigFilePath, "api-config-file", "acf", "config/api-config.yaml", "API配置文件"),
		flagSet.StringVarP(&structs.GlobalConfig.NucleiTemplate, "nuclei-template", "nt", "config/pocs", "指定存放Nuclei Poc的文件夹路径"),
		flagSet.StringVarP(&structs.GlobalConfig.WorkflowYamlPath, "workflow-yaml", "wy", "config/workflow.yaml", "指定存放workflow.yaml (指纹=>漏洞映射) 的路径"),
		flagSet.StringVarP(&structs.GlobalConfig.FingerConfigFilePath, "finger-yaml", "fy", "config/finger.yaml", "指定存放finger.yaml (指纹配置) 的路径"),
		flagSet.StringVarP(&structs.GlobalConfig.DirSearchYaml, "dir-yaml", "dy", "config/dir.yaml", "主动指纹数据库路径"),
		flagSet.StringVarP(&structs.GlobalConfig.SubdomainWordListFile, "subdomain-word-list", "swl", "config/subdomains.txt", "子域名字典文件路径"),
	)

	flagSet.CreateGroup("passwd", "爆破密码配置",
		flagSet.StringVarP(&structs.GlobalConfig.Password, "username-password", "up", "", "设置爆破凭证，设置后将禁用内置字典 | 凭证格式 'admin : password'"),
		flagSet.StringVarP(&structs.GlobalConfig.PasswordFile, "username-password-file", "upf", "", "设置爆破凭证文件(一行一个)，设置后将禁用内置字典 | 凭证格式 'admin : password'"),
	)

	// 生成带时间戳的默认审计日志文件名
	loc := time.FixedZone("CST", 8*3600)
	defaultAuditLogFileName := fmt.Sprintf("audit_%s.log", time.Now().In(loc).Format("20060102_150405"))

	flagSet.CreateGroup("audit", "审计日志 | 敏感环境必备 (默认关闭)",
		flagSet.BoolVar(&gologger.Audit, "a", false, "审计日志开关，默认关闭。使用 -a 开启。记录程序运行日志、收发包详细信息，避免背黑锅。"),
		flagSet.StringVarP(&gologger.AuditLogFileName, "audit-log-filename", "alf", defaultAuditLogFileName, "审计日志文件名称，默认格式: audit_YYYYMMDD_HHMMSS.log"),
	)

	_ = flagSet.Parse()
	if disableWAFBypassHeaders {
		structs.GlobalConfig.WAFBypassHeaders = false
	}
	if disableWAFSkipOnManyFingerprints {
		structs.GlobalConfig.WAFSkipOnManyFingerprints = false
	}

	prepare()
	flagAudit()
}

// 记录启动信息
func flagAudit() {
	gologger.AuditTimeLogger("dddd启动")
	gologger.AuditLogger("本次启动参数如下:")
	gologger.AuditLogger("Target: %s", strings.Join(structs.GlobalConfig.Targets, ","))
	gologger.AuditLogger("Subdomain: %v", structs.GlobalConfig.Subdomain)
	gologger.AuditLogger("NoSubdomainBruteForce: %v", structs.GlobalConfig.NoSubdomainBruteForce)
	gologger.AuditLogger("NoSubFinder: %v", structs.GlobalConfig.NoSubFinder)
	gologger.AuditLogger("SubdomainBruteForceThreads: %v", structs.GlobalConfig.SubdomainBruteForceThreads)
	gologger.AuditLogger("AllowLocalAreaDomain: %v", structs.GlobalConfig.AllowLocalAreaDomain)
	gologger.AuditLogger("Ports: %v", structs.GlobalConfig.Ports)
	gologger.AuditLogger("SkipHostDiscovery: %v", structs.GlobalConfig.SkipHostDiscovery)
	gologger.AuditLogger("NoICMPPing: %v", structs.GlobalConfig.NoICMPPing)
	gologger.AuditLogger("TCPPing: %v", structs.GlobalConfig.TCPPing)
	gologger.AuditLogger("GetBannerThreads: %v", structs.GlobalConfig.GetBannerThreads)
	gologger.AuditLogger("PortScanType: %v", structs.GlobalConfig.PortScanType)
	gologger.AuditLogger("TCPPortScanThreads: %v", structs.GlobalConfig.TCPPortScanThreads)
	gologger.AuditLogger("SYNPortScanThreads: %v", structs.GlobalConfig.SYNPortScanThreads)
	gologger.AuditLogger("PortsThreshold: %v", structs.GlobalConfig.PortsThreshold)
	gologger.AuditLogger("TCPPortScanTimeout: %v", structs.GlobalConfig.TCPPortScanTimeout)
	gologger.AuditLogger("MasscanPath: %v", structs.GlobalConfig.MasscanPath)
	gologger.AuditLogger("WebThreads: %v", structs.GlobalConfig.WebThreads)
	gologger.AuditLogger("WebTimeout: %v", structs.GlobalConfig.WebTimeout)
	gologger.AuditLogger("HTTPProxy: %v", structs.GlobalConfig.HTTPProxy)
	gologger.AuditLogger("HTTPProxyTestURL: %v", structs.GlobalConfig.HTTPProxyTestURL)
	gologger.AuditLogger("HTTPProxyTest: %v", structs.GlobalConfig.HTTPProxyTest)
	gologger.AuditLogger("NoDirSearch: %v", structs.GlobalConfig.NoDirSearch)
	gologger.AuditLogger("Hunter: %v", structs.GlobalConfig.Hunter)
	gologger.AuditLogger("HunterPageSize: %v", structs.GlobalConfig.HunterPageSize)
	gologger.AuditLogger("HunterMaxPageCount: %v", structs.GlobalConfig.HunterMaxPageCount)
	gologger.AuditLogger("Fofa: %v", structs.GlobalConfig.Fofa)
	gologger.AuditLogger("FofaMaxCount: %v", structs.GlobalConfig.FofaMaxCount)
	gologger.AuditLogger("Quake: %v", structs.GlobalConfig.Quake)
	gologger.AuditLogger("QuakeSize: %v", structs.GlobalConfig.QuakeSize)
	gologger.AuditLogger("LowPerceptionMode: %v", structs.GlobalConfig.LowPerceptionMode)
	gologger.AuditLogger("ReportName: %v", structs.GlobalConfig.ReportName)
	gologger.AuditLogger("GoPocThreads: %v", structs.GlobalConfig.GoPocThreads)
	gologger.AuditLogger("GolangPoc: %v", structs.GlobalConfig.GolangPoc)
	gologger.AuditLogger("PocNameForSearch: %v", structs.GlobalConfig.PocNameForSearch)
	gologger.AuditLogger("NoPoc: %v", structs.GlobalConfig.NoPoc)
	gologger.AuditLogger("NoInteractsh: %v", structs.GlobalConfig.NoInteractsh)
	gologger.AuditLogger("WAFBypassHeaders: %v", structs.GlobalConfig.WAFBypassHeaders)
	gologger.AuditLogger("WAFSkipOnManyFingerprints: %v", structs.GlobalConfig.WAFSkipOnManyFingerprints)
	gologger.AuditLogger("Audit: %v", gologger.Audit)
	gologger.AuditLogger("AuditLogFileName: %v", gologger.AuditLogFileName)
	gologger.AuditLogger("GetBannerTimeout: %v", structs.GlobalConfig.GetBannerTimeout)
	gologger.AuditLogger("SubdomainWordListFile: %v", structs.GlobalConfig.SubdomainWordListFile)
	gologger.AuditLogger("APIConfigFilePath: %v", structs.GlobalConfig.APIConfigFilePath)
	gologger.AuditLogger("NucleiTemplate: %v", structs.GlobalConfig.NucleiTemplate)
	gologger.AuditLogger("DirSearchYaml: %v", structs.GlobalConfig.DirSearchYaml)
	gologger.AuditLogger("WorkflowYamlPath: %v", structs.GlobalConfig.WorkflowYamlPath)
	gologger.AuditLogger("Password: %v", structs.GlobalConfig.Password)
	gologger.AuditLogger("PasswordFile: %v", structs.GlobalConfig.PasswordFile)

}

var PortTOP100 = "21,22,23,25,53,69,80,81,88,110,111,135,137,139,143,161,179,389,443,445,465,500,514,548,554,587,636,873,993,995,1025,1080,1099,1194,1433,1521,1723,1900,2049,2082,2083,2121,2181,2222,2375,2379,2601,3000,3128,3306,3389,3690,4443,4848,5000,5236,5432,5555,5601,5632,5800,5900,5901,5984,5985,6000,6379,7001,7002,7080,8000,8001,8008,8009,8080,8081,8088,8089,8090,8161,8443,8848,8888,9000,9001,9043,9090,9091,9200,9300,9418,10000,11211,27017,27018,50000,50070,54321"
