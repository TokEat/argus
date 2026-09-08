package common

import (
	"bytes"
	"embed"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/gopocs"
	"github.com/P0lar1ght/argus/scanner/internal/taskstore"
	"github.com/P0lar1ght/argus/scanner/lib/ddfinger"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
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

var TargetString string
var PortString string
var CLIForceFullScan bool
var disableWAFBypassHeaders bool
var disableWAFSkipOnManyFingerprints bool
var cliRulePackageDir string
var passwordAppendRaw string
var userAppendRaw string

// ConfigureCLIRulePackage makes an already validated, materialized offline
// arsenal package the standalone CLI's authoritative rule source. Explicit
// legacy path flags still override these defaults during argument parsing.
func ConfigureCLIRulePackage(configDir string) {
	cliRulePackageDir = filepath.Clean(configDir)
	structs.GlobalConfig.RuleFilesOnly = true
}

func cliRulePath(name, fallback string) string {
	if strings.TrimSpace(cliRulePackageDir) == "" {
		return fallback
	}
	return filepath.Join(cliRulePackageDir, name)
}

//go:embed config/dir.yaml
var EmbedDirDBData string

//go:embed config/finger.yaml
var EmbedFingerData string

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
	var err error
	if !structs.GlobalConfig.RuleFilesOnly {
		err = yaml.Unmarshal([]byte(EmbedDirDBData), &fps)
		if err != nil {
			return
		}
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
	var err error
	if !structs.GlobalConfig.RuleFilesOnly {
		err = yaml.Unmarshal([]byte(EmbedWorkFlowData), &fps)
	}
	if err == nil && !structs.GlobalConfig.RuleFilesOnly {
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

func prepare() error {
	var tmpTargets []string

	// 参数冲突校验
	if err := validateCLIRiskFlags(structs.GlobalConfig); err != nil {
		return err
	}
	if err := applyCLIAppendDictionaries(); err != nil {
		return err
	}
	if structs.GlobalConfig.ReportName != "" {
		if !hasHTMLReportExtension(structs.GlobalConfig.ReportName) {
			return &CLIUsageError{Message: "HTML 输出必须使用 .html 或 .htm 扩展名"}
		}
	}
	if structs.GlobalConfig.RuleFilesOnly {
		structs.GlobalEmbedPocs = embed.FS{}
		structs.GlobalEmbedActiveFingerprints = embed.FS{}
	} else {
		structs.GlobalEmbedPocs = EmbedNucleiPocs
		structs.GlobalEmbedActiveFingerprints = EmbedActiveFingerprints
	}

	if !structs.GlobalConfig.SkipHostDiscovery && structs.GlobalConfig.NoICMPPing && !structs.GlobalConfig.UDPPing {
		structs.GlobalConfig.TCPPing = true
	}

	if structs.GlobalConfig.HTTPProxyTest && structs.GlobalConfig.HTTPProxy != "" && !structs.GlobalConfig.TraceOnly {
		proxyURL, parseErr := url.Parse(structs.GlobalConfig.HTTPProxy)
		if parseErr != nil {
			return &CLIUsageError{Message: "HTTP 代理格式不正确"}
		}
		transport := retryablehttp.DefaultHostSprayingTransport()
		transport.Proxy = http.ProxyURL(proxyURL)

		gologger.Info().Msgf("测试代理中: %s", structs.GlobalConfig.HTTPProxy)
		req, err := retryablehttp.NewRequest("GET", structs.GlobalConfig.HTTPProxyTestURL, nil)
		if err != nil {
			return &CLIUsageError{Message: "HTTP 代理测试 URL 无效"}
		}
		opts := retryablehttp.DefaultOptionsSpraying
		client := retryablehttp.NewClient(opts)
		client.HTTPClient.Transport = transport

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36")
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("HTTP 代理测试失败")
		}
		gologger.Info().Msgf("代理有效！测试URL返回码: %v", resp.StatusCode)
	}

	// 兼容文件输入：普通目标列表，或上次扫描的 result.txt / 结果目录。
	// 路径形式但不存在/为空时显式报错，避免把文件名当域名目标解析。
	if inputFile := resolveScanInputFile(TargetString); inputFile != "" {
		if info, statErr := os.Stat(inputFile); statErr == nil {
			if info.IsDir() {
				return &CLIUsageError{Message: fmt.Sprintf("结果目录中没有 result.txt: %s", TargetString)}
			}
			fileBytes, readErr := os.ReadFile(inputFile)
			if readErr != nil {
				return &CLIUsageError{Message: fmt.Sprintf("读取输入文件失败: %v", readErr)}
			}
			if len(bytes.TrimSpace(fileBytes)) == 0 {
				return &CLIUsageError{Message: fmt.Sprintf("输入文件为空: %s", TargetString)}
			}
			content := strings.ReplaceAll(string(fileBytes), "\r\n", "\n")
			tmpTargets = strings.Split(content, "\n")
		} else if dirInfo, dirErr := os.Stat(TargetString); dirErr == nil && dirInfo.IsDir() {
			return &CLIUsageError{Message: fmt.Sprintf("结果目录中没有 result.txt: %s", TargetString)}
		} else if isFileLikeInput(TargetString) {
			return &CLIUsageError{Message: fmt.Sprintf("输入文件不存在: %s", TargetString)}
		} else {
			tgs := strings.Split(TargetString, ",")
			for _, each := range tgs {
				if each != "" {
					tmpTargets = append(tmpTargets, each)
				}
			}
		}
	} else {
		tgs := strings.Split(TargetString, ",")
		for _, each := range tgs {
			if each != "" {
				tmpTargets = append(tmpTargets, each)
			}
		}
	}
	ingested := ingestScanInputLines(tmpTargets)
	structs.GlobalConfig.Targets = append(structs.GlobalConfig.Targets, ingested.Targets...)
	structs.GlobalResultMap = ingested.Fingers
	if structs.GlobalResultMap == nil {
		structs.GlobalResultMap = make(map[string][]string)
	}
	structs.DirFallbackResultMap = make(map[string][]string)
	structs.DirEvidenceResultMap = make(map[string][]string)
	if ingested.SkipDiscover {
		structs.GlobalConfig.SkipHostDiscovery = true
		gologger.Info().Msgf("复用上次结果: 存活主机 %d, 开放端口 %d, 已跳过探活", ingested.ReusedAlive, ingested.ReusedPorts)
	}

	if len(structs.GlobalConfig.Targets) == 0 && len(structs.GlobalResultMap) == 0 {
		if structs.GlobalConfig.TraceOnly {
			return &CLIUsageError{Message: "-tr/--trace 没有可用目标；请指定 IP、网段或结果文件"}
		}
		return &CLIUsageError{Message: "无目标输入；请使用 -a/--target 指定已授权目标"}
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

	taskName = sanitizeResultDirectoryName(taskName)
	outputName := filepath.Base(structs.GlobalConfig.OutputFile)
	reportName := timestamp + ".html"
	if structs.GlobalConfig.ReportName != "" {
		reportName = filepath.Base(structs.GlobalConfig.ReportName)
	}
	auditName := ""
	if gologger.Audit && gologger.AuditLogFileName != "" {
		auditName = filepath.Base(gologger.AuditLogFileName)
	}
	if err := validateCLIArtifactNames(outputName, reportName, auditName); err != nil {
		return err
	}
	dirName, err := createUniqueResultDirectory("datas", fmt.Sprintf("%s_%s", taskName, timestamp))
	if err != nil {
		return fmt.Errorf("创建唯一结果目录失败: %w", err)
	}
	gologger.Info().Msgf("结果目录: %s", dirName)
	structs.GlobalConfig.OutputFile = filepath.Join(dirName, outputName)
	structs.GlobalConfig.ReportName = filepath.Join(dirName, reportName)
	if gologger.AuditLogFileName != "" {
		gologger.AuditLogFileName = filepath.Join(dirName, filepath.Base(gologger.AuditLogFileName))
	}

	if IsLinux() {
		if fdlimit := GetFdLimit(); fdlimit > 0 && structs.GlobalConfig.TCPPortScanThreads > fdlimit {
			gologger.Warning().Msgf("System fd limit: %d , Please exec 'ulimit -n 65535'", fdlimit)
			gologger.Warning().Msgf("Now set threads to %d", fdlimit-100)
			structs.GlobalConfig.TCPPortScanThreads = fdlimit - 100
		}
	}

	ddout.OutputType = structs.GlobalConfig.OutputType
	ddout.OutputFileName = structs.GlobalConfig.OutputFile

	if PortString == "" {
		// 默认使用 Argus 常用协议端口集；Server 的标准预设使用
		// 未额外改写的 scanpolicy.Top1000TCPPorts。
		structs.GlobalConfig.Ports = PortCommon100
	} else {
		structs.GlobalConfig.Ports = PortString
	}

	if err := initializeLegacyResponseStores(); err != nil {
		return fmt.Errorf("initialize response stores: %w", err)
	}
	structs.GlobalIPPortMap = make(map[string]string)
	structs.GlobalIPDomainMap = make(map[string][]string)
	structs.GlobalURLMap = make(map[string]structs.URLEntity)

	if structs.GlobalConfig.TraceOnly {
		if !hasIPv4TraceTarget(structs.GlobalConfig.Targets) {
			return &CLIUsageError{Message: "-tr/--trace 需要 IPv4、网段或含主机的结果文件"}
		}
		return nil
	}

	if err := parseFingerDB(); err != nil {
		return err
	}
	if len(structs.FingerprintDB) == 0 {
		return fmt.Errorf("fingerprint rule database is empty")
	}
	gologger.Info().Msgf("YAML指纹数据: %d 条\n", len(structs.FingerprintDB))

	ReadWorkFlowDB()
	if len(structs.WorkFlowDB) == 0 {
		return fmt.Errorf("workflow rule database is empty")
	}
	gologger.Info().Msgf("漏洞检测支持指纹: %d 条", len(structs.WorkFlowDB))

	ReadDirDB()
	if len(structs.DirDB) == 0 {
		return fmt.Errorf("directory fingerprint database is empty")
	}
	return nil
}

// initializeLegacyResponseStores preserves the legacy globals while sharing
// the same task-private response-store policy as engine.ScanContext.
func initializeLegacyResponseStores() error {
	stores, err := taskstore.New(structs.GlobalConfig)
	if err != nil {
		return err
	}
	structs.GlobalHttpBodyHMap = stores.Body
	structs.GlobalHttpHeaderHMap = stores.Header
	structs.GlobalBannerHMap = stores.Banner
	return nil
}

func parseFingerDB() error {
	fps := make(map[string]interface{})
	if !structs.GlobalConfig.RuleFilesOnly {
		err := yaml.Unmarshal([]byte(EmbedFingerData), &fps)
		if err != nil {
			return fmt.Errorf("parse embedded fingerprint rules: %w", err)
		}
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
		if err != nil {
			return fmt.Errorf("read fingerprint rules: %w", err)
		}
		fps = make(map[string]interface{})
		err = yaml.Unmarshal(data, &fps)
		if err != nil {
			return fmt.Errorf("parse fingerprint rules: %w", err)
		}
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
	return nil
}

func FlagWithError() error {
	presentation := ConfigureCLIPresentation(os.Args[1:])
	structs.GlobalConfig.MachineOutput = !presentation.Interactive
	if presentation.ShowBanner {
		showBanner()
	}

	flagSet := goflags.NewFlagSet()
	flagSet.CaseSensitive = true
	flagSet.SetDescription(cliDescription)
	flagSet.SetCustomHelpText(cliHelpText)

	defaultTCPThreads := 1000
	if IsLinux() {
		defaultTCPThreads = 4000
	}

	flagSet.CreateGroup("input", "扫描目标",
		flagSet.StringVarP(&TargetString, "target", "a", "", "被扫描的目标。 192.168.0.1 192.168.0.0/16 192.168.0.1:80 baidu.com:80 file.txt(一行一个) result.txt(fscan/argus)"),
		flagSet.StringVarP(&TraceTarget, "trace", "tr", "", "单独路径探测。后跟 IP、网段或结果文件，不跑端口/指纹/POC"),
		flagSet.BoolVarP(&CLIForceFullScan, "force", "f", false, "与 -ss 一起使用时，忽略 datas 历史跳过并完整扫描"),
		flagSet.BoolVarP(&structs.GlobalConfig.SkipSeenHistory, "skip-seen", "ss", false, "跳过 datas 里已经出现过的 IP（默认关闭）"),
	)

	flagSet.CreateGroup("portscan", "端口扫描",
		flagSet.StringVarP(&PortString, "port", "p", "", "端口设置。默认扫描常用协议端口集"),
		flagSet.StringVarP(&structs.GlobalConfig.PortScanType, "scan-type", "st", "tcp", "端口扫描方式 | \"-st tcp\"设置TCP扫描 | \"-st syn\"设置SYN扫描"),
		flagSet.IntVarP(&structs.GlobalConfig.TCPPortScanThreads, "tcp-scan-threads", "t", defaultTCPThreads, "TCP扫描线程 | Windows/Mac默认1000线程 Linux默认4000"),
		flagSet.IntVarP(&structs.GlobalConfig.SYNPortScanThreads, "syn-scan-threads", "sst", 10000, "SYN扫描发包速率(包/秒)"),
		flagSet.IntVarP(&structs.GlobalConfig.PortsThreshold, "ports-max-count", "pmc", 300, "IP端口数量阈值 | 当一个IP的端口数量超过此值，此IP将会被抛弃"),
		flagSet.IntVarP(&structs.GlobalConfig.TCPPortScanTimeout, "port-scan-timeout", "pst", 6, "TCP端口扫描超时(秒)"),
	)

	flagSet.CreateGroup("alive", "主机发现",
		flagSet.BoolVar(&structs.GlobalConfig.SkipHostDiscovery, "Pn", false, "跳过存活探测，对全部目标直接端口扫描"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoICMPPing, "no-icmp-ping", "nip", false, "不用 ICMP，改用 TCP 探活(80,443,3389,445,22)；同网段仍先 ARP"),
		flagSet.BoolVarP(&structs.GlobalConfig.UDPPing, "udp-ping", "PU", false, "UDP探活：打常关口 40125，ICMP port unreachable 视为存活。TCP/ICMP 被禁时用"),
	)

	flagSet.CreateGroup("nmap", "协议识别",
		flagSet.IntVarP(&structs.GlobalConfig.GetBannerThreads, "nmap-threads", "tc", 500, "Nmap协议识别线程"),
		flagSet.IntVarP(&structs.GlobalConfig.GetBannerTimeout, "nmap-timeout", "nto", 5, "Nmap协议识别超时时间(秒)"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoUDPIdentify, "no-udp-identify", "nudp", false, "关闭默认的高价值内网 UDP 识别"),
	)

	flagSet.CreateGroup("subdomain", "探索子域名",
		flagSet.BoolVarP(&structs.GlobalConfig.Subdomain, "subdomain", "sd", false, "开启子域名枚举，默认关闭"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoSubdomainBruteForce, "no-subdomain-brute", "nsb", true, "关闭子域名爆破"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoSubFinder, "no-subfinder", "ns", true, "关闭被动子域名枚举"),
		flagSet.IntVarP(&structs.GlobalConfig.SubdomainBruteForceThreads, "subdomain-brute-threads", "sbt", 150, "子域名爆破线程数量"),
		flagSet.BoolVarP(&structs.GlobalConfig.AllowLocalAreaDomain, "local-domain", "ld", false, "允许扫描解析到内网/回环的域名 IP（默认跳过私网地址）"),
		flagSet.BoolVarP(&structs.GlobalConfig.AllowCDNAssets, "allow-cdn", "ac", false, "允许扫描 CDN 资产：按任务端口设置对 CDN 域名做域名形式探测并打标，默认仅记录不探测"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoHostBind, "no-host-bind", "nhb", true, "禁用域名绑定资产探测"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoDomainProbe, "no-domain-probe", "ndp", false, "禁用域名+端口形式的 Web 探测（回退为解析 IP 形式）"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoResolvedIPScan, "no-resolved-ip-scan", "nsi", false, "不对域名的解析 IP 做存活探测和端口扫描，仅按 域名:端口 形式盲探 Web"),
	)

	flagSet.CreateGroup("web", "Web探针配置",
		flagSet.IntVarP(&structs.GlobalConfig.WebThreads, "web-threads", "wt", 200, "Web探针线程,根据网络环境调整"),
		flagSet.IntVarP(&structs.GlobalConfig.WebTimeout, "web-timeout", "wto", 10, "Web探针超时时间,根据网络环境调整"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoDirSearch, "no-dir", "nd", false, "关闭主动Web指纹探测"),
	)

	flagSet.CreateGroup("proxy", "HTTP代理配置",
		flagSet.StringVarP(&structs.GlobalConfig.HTTPProxy, "proxy", "x", "", "HTTP代理"),
		flagSet.BoolVarP(&structs.GlobalConfig.HTTPProxyTest, "proxy-test", "pt", true, "启动前测试HTTP代理"),
		flagSet.StringVarP(&structs.GlobalConfig.HTTPProxyTestURL, "proxy-test-url", "ptu", "https://www.baidu.com", "测试HTTP代理的url，需要url返回200"),
	)

	flagSet.CreateGroup("output", "输出",
		flagSet.StringVarP(&structs.GlobalConfig.OutputFile, "output", "o", "result.txt", "结果输出文件"),
		flagSet.StringVarP(&structs.GlobalConfig.OutputType, "output-type", "ot", "text", "结果输出格式 text,json"),
		flagSet.StringVarP(&structs.GlobalConfig.ReportName, "html-output", "ho", "", "Argus HTML 扫描报告名称（资产、服务、指纹和漏洞证据统一展示）"),
	)

	flagSet.CreateGroup("vuln-detect", "漏洞探测",
		flagSet.BoolVar(&structs.GlobalConfig.NoPoc, "nopoc", false, "关闭 Nuclei POC，不影响 GoPoc"),
		flagSet.BoolVarP(&structs.GlobalConfig.ShowPocMap, "show-poc-map", "spm", false, "打印指纹到 Nuclei POC 的映射和加载的模板列表（默认关闭）"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoGoPoc, "no-gopoc", "nogpoc", false, "关闭全部 GoPoc"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoBrute, "no-brute", "nobr", false, "关闭服务口令爆破，不影响其它 GoPoc"),
		flagSet.StringVarP(&structs.GlobalConfig.GoPocModules, "module", "m", "", "只运行指定 GoPoc/爆破协议或插件，多个用逗号分隔。支持: "+gopocs.GoPocModuleHelpList()),
		flagSet.StringVarP(&structs.GlobalConfig.PocNameForSearch, "poc-name", "poc", "", "模糊匹配Poc名称"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoInteractsh, "no-interactsh", "ni", true, "禁用Interactsh服务器，排除反连模版"),
		flagSet.IntVarP(&structs.GlobalConfig.GoPocThreads, "golang-poc-threads", "gpt", 50, "GoPoc运行线程"),
		flagSet.BoolVarP(&structs.GlobalConfig.DisableGeneralPoc, "disable-general-poc", "dgp", false, "禁用无视指纹的漏洞映射"),
		flagSet.BoolVarP(&disableWAFBypassHeaders, "no-waf-bypass-headers", "nwb", false, "关闭默认开启的 WAF 绕过请求头"),
		flagSet.BoolVarP(&disableWAFSkipOnManyFingerprints, "no-waf-skip-many-fingerprints", "nws", false, "关闭多指纹目标跳过POC映射，默认开启"),
		flagSet.StringVarP(&structs.GlobalConfig.ExcludeTags, "exclude-tags", "et", "", "通过tags排除模版 | 多个tags请用,连接"),
		flagSet.StringVarP(&structs.GlobalConfig.Severities, "severity", "s", "", "只允许指定严重程度的模板运行 | 多参数用,连接 | 允许的值: "+strings.ReplaceAll(severity.GetSupportedSeverities().String(), " ", "")),
	)

	flagSet.CreateGroup("config", "配置文件",
		flagSet.StringVarP(&structs.GlobalConfig.NucleiTemplate, "nuclei-template", "nt", cliRulePath("pocs", "config/pocs"), "指定存放Nuclei Poc的文件夹路径"),
		flagSet.StringVarP(&structs.GlobalConfig.WorkflowYamlPath, "workflow-yaml", "wy", cliRulePath("workflow.yaml", "config/workflow.yaml"), "指定存放workflow.yaml (指纹=>漏洞映射) 的路径"),
		flagSet.StringVarP(&structs.GlobalConfig.FingerConfigFilePath, "finger-yaml", "fy", cliRulePath("finger.yaml", "config/finger.yaml"), "指定存放finger.yaml (指纹配置) 的路径"),
		flagSet.StringVarP(&structs.GlobalConfig.DirSearchYaml, "dir-yaml", "dy", cliRulePath("dir.yaml", "config/dir.yaml"), "主动指纹数据库路径"),
		flagSet.StringVarP(&structs.GlobalConfig.SubdomainWordListFile, "subdomain-word-list", "swl", cliRulePath("subdomains.txt", "config/subdomains.txt"), "子域名字典文件路径"),
	)

	flagSet.CreateGroup("passwd", "爆破密码配置",
		flagSet.StringVarP(&structs.GlobalConfig.Password, "username-password", "up", "", "设置爆破凭证，设置后将禁用内置字典 | 凭证格式 'admin : password'"),
		flagSet.StringVarP(&structs.GlobalConfig.PasswordFile, "username-password-file", "upf", "", "设置爆破凭证文件(一行一个)，设置后将禁用内置字典 | 凭证格式 'admin : password'"),
		flagSet.StringVarP(&passwordAppendRaw, "password-append", "pwda", "", "在内置密码本上追加密码。值为已存在文件时按行读取，否则按空白分词"),
		flagSet.StringVarP(&userAppendRaw, "user-append", "usea", "", "在内置用户本上追加用户。值为已存在文件时按行读取，否则按空白分词"),
	)

	// 生成带时间戳的默认审计日志文件名
	loc := time.FixedZone("CST", 8*3600)
	defaultAuditLogFileName := fmt.Sprintf("audit_%s.log", time.Now().In(loc).Format("20060102_150405"))

	flagSet.CreateGroup("audit", "审计日志 | 敏感环境必备 (默认关闭)",
		flagSet.BoolVarP(&gologger.Audit, "audit", "ad", false, "审计日志开关，默认关闭。记录程序运行日志、收发包详细信息。"),
		flagSet.StringVarP(&gologger.AuditLogFileName, "audit-log-filename", "alf", defaultAuditLogFileName, "审计日志文件名称，默认格式: audit_YYYYMMDD_HHMMSS.log"),
	)

	if err := parseCLIFlags(flagSet.Parse, presentation, os.Args[1:]); err != nil {
		return fmt.Errorf("parse CLI configuration: %w", err)
	}
	applyTraceFlag()
	if err := ValidateCLIOutputType(structs.GlobalConfig.OutputType); err != nil {
		return err
	}
	structs.GlobalConfig.WAFBypassHeaders = !disableWAFBypassHeaders
	if disableWAFSkipOnManyFingerprints {
		structs.GlobalConfig.WAFSkipOnManyFingerprints = false
	}

	if err := prepare(); err != nil {
		return err
	}
	flagAudit()
	return nil
}

func flagAudit() {
	gologger.AuditTimeLogger("Argus 启动")
	gologger.AuditLogger("本次启动参数如下:")
	gologger.AuditLogger("Target: %s", strings.Join(structs.GlobalConfig.Targets, ","))
	gologger.AuditLogger("Subdomain: %v", structs.GlobalConfig.Subdomain)
	gologger.AuditLogger("NoSubdomainBruteForce: %v", structs.GlobalConfig.NoSubdomainBruteForce)
	gologger.AuditLogger("NoSubFinder: %v", structs.GlobalConfig.NoSubFinder)
	gologger.AuditLogger("SubdomainBruteForceThreads: %v", structs.GlobalConfig.SubdomainBruteForceThreads)
	gologger.AuditLogger("AllowLocalAreaDomain: %v", structs.GlobalConfig.AllowLocalAreaDomain)
	gologger.AuditLogger("Ports: %v", structs.GlobalConfig.Ports)
	gologger.AuditLogger("SkipHostDiscovery: %v", structs.GlobalConfig.SkipHostDiscovery)
	gologger.AuditLogger("SkipSeenHistory: %v", structs.GlobalConfig.SkipSeenHistory)
	gologger.AuditLogger("NoICMPPing: %v", structs.GlobalConfig.NoICMPPing)
	gologger.AuditLogger("TCPPing: %v", structs.GlobalConfig.TCPPing)
	gologger.AuditLogger("UDPPing: %v", structs.GlobalConfig.UDPPing)
	gologger.AuditLogger("TraceRoute: %v", structs.GlobalConfig.TraceRoute)
	gologger.AuditLogger("TraceOnly: %v", structs.GlobalConfig.TraceOnly)
	gologger.AuditLogger("ShowPocMap: %v", structs.GlobalConfig.ShowPocMap)
	gologger.AuditLogger("GetBannerThreads: %v", structs.GlobalConfig.GetBannerThreads)
	gologger.AuditLogger("PortScanType: %v", structs.GlobalConfig.PortScanType)
	gologger.AuditLogger("TCPPortScanThreads: %v", structs.GlobalConfig.TCPPortScanThreads)
	gologger.AuditLogger("SYNPortScanThreads: %v", structs.GlobalConfig.SYNPortScanThreads)
	gologger.AuditLogger("PortsThreshold: %v", structs.GlobalConfig.PortsThreshold)
	gologger.AuditLogger("TCPPortScanTimeout: %v", structs.GlobalConfig.TCPPortScanTimeout)
	gologger.AuditLogger("WebThreads: %v", structs.GlobalConfig.WebThreads)
	gologger.AuditLogger("WebTimeout: %v", structs.GlobalConfig.WebTimeout)
	gologger.AuditLogger("HTTPProxy: %v", structs.GlobalConfig.HTTPProxy)
	gologger.AuditLogger("HTTPProxyTestURL: %v", structs.GlobalConfig.HTTPProxyTestURL)
	gologger.AuditLogger("HTTPProxyTest: %v", structs.GlobalConfig.HTTPProxyTest)
	gologger.AuditLogger("NoDirSearch: %v", structs.GlobalConfig.NoDirSearch)
	gologger.AuditLogger("ReportName: %v", structs.GlobalConfig.ReportName)
	gologger.AuditLogger("GoPocThreads: %v", structs.GlobalConfig.GoPocThreads)
	gologger.AuditLogger("GolangPoc: %v", structs.GlobalConfig.GolangPoc)
	gologger.AuditLogger("NoGoPoc: %v", structs.GlobalConfig.NoGoPoc)
	gologger.AuditLogger("NoBrute: %v", structs.GlobalConfig.NoBrute)
	gologger.AuditLogger("GoPocModules: %v", structs.GlobalConfig.GoPocModules)
	gologger.AuditLogger("UserAppend: %d", len(structs.GlobalConfig.UserAppend))
	gologger.AuditLogger("PasswordAppend: %d", len(structs.GlobalConfig.PasswordAppend))
	gologger.AuditLogger("PocNameForSearch: %v", structs.GlobalConfig.PocNameForSearch)
	gologger.AuditLogger("NoPoc: %v", structs.GlobalConfig.NoPoc)
	gologger.AuditLogger("NoInteractsh: %v", structs.GlobalConfig.NoInteractsh)
	gologger.AuditLogger("WAFBypassHeaders: %v", structs.GlobalConfig.WAFBypassHeaders)
	gologger.AuditLogger("WAFSkipOnManyFingerprints: %v", structs.GlobalConfig.WAFSkipOnManyFingerprints)
	gologger.AuditLogger("Audit: %v", gologger.Audit)
	gologger.AuditLogger("AuditLogFileName: %v", gologger.AuditLogFileName)
	gologger.AuditLogger("GetBannerTimeout: %v", structs.GlobalConfig.GetBannerTimeout)
	gologger.AuditLogger("NoUDPIdentify: %v", structs.GlobalConfig.NoUDPIdentify)
	gologger.AuditLogger("SubdomainWordListFile: %v", structs.GlobalConfig.SubdomainWordListFile)
	gologger.AuditLogger("NucleiTemplate: %v", structs.GlobalConfig.NucleiTemplate)
	gologger.AuditLogger("DirSearchYaml: %v", structs.GlobalConfig.DirSearchYaml)
	gologger.AuditLogger("WorkflowYamlPath: %v", structs.GlobalConfig.WorkflowYamlPath)
	gologger.AuditLogger("Password: %v", structs.GlobalConfig.Password)
	gologger.AuditLogger("PasswordFile: %v", structs.GlobalConfig.PasswordFile)

}

var PortCommon100 = scanpolicy.Common100Ports

// PortTOP100 is retained for source compatibility with older callers.
// Deprecated: use PortCommon100 or scanpolicy.Top1000TCPPorts.
var PortTOP100 = PortCommon100
