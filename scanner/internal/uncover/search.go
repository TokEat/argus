// Package uncover 网络空间搜索引擎集成。
package uncover

import (
	"dddd/scanner/ddout"
	"dddd/scanner/structs"
	"dddd/scanner/utils"
	"dddd/scanner/utils/cdn"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/httpx/common/hashes"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"gopkg.in/yaml.v3"
)

// Config captures the task-scoped settings required by uncover search stages.
type Config struct {
	APIConfigFilePath          string
	SubdomainBruteForceThreads int
	HunterPageSize             int
	HunterMaxPageCount         int
	FofaMaxCount               int
	QuakeSize                  int
	LowPerceptionMode          bool
	OnlyIPPort                 bool
	AllowCDNAssets             bool
}

// State captures the mutable runtime state populated by search engines.
type State struct {
	IPPortMap     map[string]string
	IPPortMapLock *sync.Mutex

	IPDomainMap     map[string][]string
	IPDomainMapLock *sync.Mutex

	URLMap     map[string]structs.URLEntity
	URLMapLock *sync.Mutex

	BannerHMap *hybrid.HybridMap
	BodyHMap   *hybrid.HybridMap
	HeaderHMap *hybrid.HybridMap

	// EmitFunc 可选的上下文感知输出路由。设置后替代全局 ddout.FormatOutput，
	// 使多任务并发时输出不会互相串扰。
	EmitFunc func(ddout.OutputMessage)
}

// emitOutput 通过 State.EmitFunc（如已设置）或全局 ddout 输出一条消息。
func emitOutput(state *State, msg ddout.OutputMessage) {
	if state != nil && state.EmitFunc != nil {
		state.EmitFunc(msg)
		return
	}
	ddout.FormatOutput(msg)
}

type hunterResp struct {
	Code    int        `json:"code"`
	Data    hunterData `json:"data"`
	Message string     `json:"message"`
}

type hunterInfo struct {
	URL      string `json:"url"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Domain   string `json:"domain"`
	Protocol string `json:"protocol"`
	IsWeb    string `json:"is_web"`
	City     string `json:"city"`
	Company  string `json:"company"`
	Code     int    `json:"status_code"`
	Title    string `json:"web_title"`
	Country  string `json:"country"`
	Banner   string `json:"banner"`
}

type hunterData struct {
	InfoArr   []hunterInfo `json:"arr"`
	Total     int          `json:"total"`
	RestQuota string       `json:"rest_quota"`
}

type fofaResponse struct {
	Error   bool       `json:"error"`
	Results [][]string `json:"results"`
	Size    int        `json:"size"`
}

type quakeServiceInfo struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    []struct {
		Service struct {
			HTTP struct {
				Host  string   `json:"host"`
				Title string   `json:"title"`
				URL   []string `json:"http_load_url"`
			} `json:"http"`
			Name string `json:"name"`
		} `json:"service"`
		IP   string `json:"ip"`
		Port int    `json:"port"`
	} `json:"data"`
}

func HunterSearch(targets []string, cfg Config, state *State) ([]string, []string) {
	gologger.Info().Msg("准备从 Hunter 获取数据")
	gologger.AuditTimeLogger("准备从 Hunter 获取数据")

	var results []string
	var ipResults []string
	for _, keyword := range targets {
		targetsForKeyword, ipsForKeyword := searchHunterCore(keyword, cfg, state)
		results = append(results, targetsForKeyword...)
		ipResults = append(ipResults, ipsForKeyword...)
	}
	return utils.RemoveDuplicateElement(results), utils.RemoveDuplicateElement(ipResults)
}

func FOFASearch(targets []string, cfg Config, state *State) []string {
	gologger.Info().Msg("准备从 Fofa 获取数据")
	var results []string
	for _, keyword := range targets {
		results = append(results, searchFOFACore(keyword, cfg, state)...)
	}
	return utils.RemoveDuplicateElement(results)
}

func QuakeSearch(targets []string, cfg Config, state *State) []string {
	gologger.Info().Msg("正在查询Quake账户权限。")
	isVIP := isQuakeVIP(cfg.APIConfigFilePath)
	if isVIP {
		gologger.Info().Msg("VIP")
	} else {
		gologger.Info().Msg("非VIP")
	}
	gologger.Info().Msg("准备从 Quake 获取数据")

	var results []string
	for _, keyword := range targets {
		results = append(results, searchQuakeCore(keyword, cfg, state, isVIP)...)
	}
	return utils.RemoveDuplicateElement(results)
}

func searchHunterCore(keyword string, cfg Config, state *State) ([]string, []string) {
	keys, err := readAPIKeys(cfg.APIConfigFilePath, "hunter")
	if err != nil {
		gologger.Error().Msgf("[Hunter] API Key 读取失败: %v", err)
		return nil, nil
	}

	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSpraying)
	url := "https://hunter.qianxin.com/openApi/search"
	randKey := keys[rand.Intn(len(keys))]

	page := 1
	currentQueryCount := 0
	var results []string
	var ipResults []string

	for page <= cfg.HunterMaxPageCount {
		req, err := retryablehttp.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			gologger.Error().Msg("[Hunter] API请求构建失败")
			return results, ipResults
		}

		search := base64.URLEncoding.EncodeToString([]byte(keyword))
		q := req.URL.Query()
		q.Add("search", search)
		q.Add("api-key", randKey)
		q.Add("page", strconv.Itoa(page))
		q.Add("page_size", strconv.Itoa(cfg.HunterPageSize))
		q.Add("is_web", "3")
		req.URL.RawQuery = q.Encode()

		resp, err := client.Do(req)
		if err != nil {
			gologger.Error().Msgf("[Hunter] %s 资产查询失败: %v", keyword, err)
			time.Sleep(3 * time.Second)
			continue
		}

		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			gologger.Error().Msgf("[Hunter] 读取响应失败: %v", readErr)
			time.Sleep(3 * time.Second)
			continue
		}

		var response hunterResp
		if err := json.Unmarshal(body, &response); err != nil {
			gologger.Error().Msgf("[Hunter] Json解析失败: %v", err)
			time.Sleep(3 * time.Second)
			continue
		}

		if response.Code != 200 {
			gologger.Error().Msgf("[Hunter] %s 搜索失败: %s", keyword, response.Message)
			if strings.Contains(response.Message, "请求太多") ||
				strings.Contains(response.Message, "今日免费积分") {
				time.Sleep(3 * time.Second)
				continue
			}
			return results, ipResults
		}
		if response.Data.Total == 0 {
			gologger.Error().Msgf("[Hunter] %s 无结果", keyword)
			return results, ipResults
		}

		domainCDNMap := buildDomainCDNMap(collectHunterDomains(response.Data.InfoArr), cfg.SubdomainBruteForceThreads)

		for _, item := range response.Data.InfoArr {
			isCDN := domainCDNMap[item.Domain]
			if !isCDN {
				addIPDomainMap(state, item.IP, item.Domain)
				ipResults = append(ipResults, item.IP)
			}

			if item.IsWeb == "是" {
				if cfg.LowPerceptionMode {
					storeHunterWeb(state, item)
					continue
				}

				target := item.URL
				if cfg.OnlyIPPort && !isCDN {
					target = fmt.Sprintf("%s://%s:%d", item.Protocol, item.IP, item.Port)
				}
				if target == "" {
					continue
				}
				if utils.GetItemInArray(results, target) == -1 && (!isCDN || cfg.AllowCDNAssets) {
					results = append(results, target)
					emitOutput(state, ddout.OutputMessage{
						Type:     "Hunter",
						IP:       item.IP,
						Port:     strconv.Itoa(item.Port),
						Protocol: item.Protocol,
						Web: ddout.WebInfo{
							Title:  item.Title,
							Status: strconv.Itoa(item.Code),
						},
						Domain:        item.Domain,
						URI:           target,
						City:          item.City,
						AdditionalMsg: item.Company,
					})
				}
				continue
			}

			if cfg.LowPerceptionMode {
				storeHunterService(state, item)
				continue
			}

			target := fmt.Sprintf("%s:%d", item.IP, item.Port)
			if utils.GetItemInArray(results, target) == -1 && (!isCDN || cfg.AllowCDNAssets) {
				results = append(results, target)
				emitOutput(state, ddout.OutputMessage{
					Type:          "Hunter",
					IP:            item.IP,
					Port:          strconv.Itoa(item.Port),
					Protocol:      item.Protocol,
					Domain:        item.Domain,
					City:          item.City,
					AdditionalMsg: item.Company,
				})
			}
		}

		currentQueryCount += len(response.Data.InfoArr)
		gologger.Info().Msgf("[Hunter] [%s] 当前第 [%d] 页 查询进度: %d/%d %v", keyword, page, currentQueryCount, response.Data.Total, response.Data.RestQuota)
		if currentQueryCount >= response.Data.Total {
			return results, ipResults
		}
		page++
		time.Sleep(3 * time.Second)
	}

	return results, ipResults
}

func searchFOFACore(keyword string, cfg Config, state *State) []string {
	keys, err := readAPIKeys(cfg.APIConfigFilePath, "fofa")
	if err != nil {
		gologger.Error().Msgf("[Fofa] API Key 读取失败: %v", err)
		return nil
	}

	randKey := keys[rand.Intn(len(keys))]
	if !strings.Contains(randKey, ":") {
		gologger.Error().Msg("[Fofa] API Key 格式错误，应为 email:key")
		return nil
	}
	tmp := strings.SplitN(randKey, ":", 2)
	email, key := tmp[0], tmp[1]

	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSpraying)
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://fofa.info/api/v1/search/all", nil)
	if err != nil {
		gologger.Error().Msg("[Fofa] API请求构建失败")
		return nil
	}

	search := base64.StdEncoding.EncodeToString([]byte(keyword))
	q := req.URL.Query()
	q.Add("qbase64", search)
	q.Add("email", email)
	q.Add("key", key)
	q.Add("page", "1")
	q.Add("size", strconv.Itoa(cfg.FofaMaxCount))
	q.Add("fields", "host,protocol,title,icp,ip,port,domain")
	q.Add("full", "false")
	req.URL.RawQuery = q.Encode()

	time.Sleep(3 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		gologger.Error().Msgf("[Fofa] [%s] 资产查询失败: %v", keyword, err)
		return nil
	}

	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr != nil {
		gologger.Error().Msgf("[Fofa] 读取响应失败: %v", readErr)
		return nil
	}

	var response fofaResponse
	if err := json.Unmarshal(body, &response); err != nil {
		gologger.Error().Msgf("[Fofa] Json解析失败: %v", err)
		return nil
	}
	if response.Error {
		gologger.Error().Msgf("[Fofa] [%s] 搜索失败: %s", keyword, string(body))
		return nil
	}
	if response.Size == 0 {
		gologger.Error().Msgf("[Fofa] [%s] 无结果", keyword)
		return nil
	}

	domainCDNMap := buildDomainCDNMap(collectFOFADomains(response.Results), cfg.SubdomainBruteForceThreads)
	var results []string
	for _, result := range response.Results {
		if len(result) < 7 {
			continue
		}
		host, protocol, icp, title, ip, port := result[0], result[1], result[2], result[3], result[4], result[5]
		domain := ""
		if result[6] != "" {
			realHost := strings.ReplaceAll(host, protocol+"://", "")
			domain = strings.ReplaceAll(realHost, ":"+port, "")
		}

		isCDN := false
		if domain != "" {
			isCDN = domainCDNMap[domain]
			if !isCDN {
				addIPDomainMap(state, ip, domain)
			}
		}

		addTarget, show := buildFOFATarget(host, protocol, ip, port, domain, title, icp, isCDN, cfg)
		if addTarget == "" {
			continue
		}
		if utils.GetItemInArray(results, addTarget) == -1 && (!isCDN || cfg.AllowCDNAssets) {
			results = append(results, addTarget)
			emitOutput(state, ddout.OutputMessage{
				Type:     "Fofa",
				IP:       ip,
				Port:     port,
				Protocol: protocol,
				Domain:   domain,
				URI:      host,
				Show:     show,
			})
		}
	}

	gologger.Info().Msgf("[Fofa] [%s] 已查询: %d/%d", keyword, len(response.Results), response.Size)
	return results
}

func searchQuakeCore(keyword string, cfg Config, state *State, isVIP bool) []string {
	keys, err := readAPIKeys(cfg.APIConfigFilePath, "quake")
	if err != nil {
		gologger.Error().Msgf("[Quake] API Key 读取失败: %v", err)
		return nil
	}

	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSpraying)
	payload := map[string]interface{}{
		"query": keyword,
		"start": "0",
		"size":  strconv.Itoa(cfg.QuakeSize),
	}
	if !isVIP {
		payload["include"] = []string{"ip", "port"}
	}
	body, _ := json.Marshal(payload)

	req, err := retryablehttp.NewRequest(http.MethodPost, "https://quake.360.net/api/v3/search/quake_service", body)
	if err != nil {
		gologger.Error().Msg("[Quake] API请求构建失败")
		return nil
	}
	req.Header.Set("X-QuakeToken", keys[rand.Intn(len(keys))])
	req.Header.Set("Content-Type", "application/json")

	time.Sleep(2 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		gologger.Error().Msgf("[Quake] [%s] 资产查询失败: %v", keyword, err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		gologger.Error().Msg("[Quake] API-KEY错误")
		return nil
	}

	respBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		gologger.Error().Msgf("[Quake] 读取响应失败: %v", readErr)
		return nil
	}

	var serviceInfo quakeServiceInfo
	if err := json.Unmarshal(respBody, &serviceInfo); err != nil {
		gologger.Error().Msgf("[Quake] 响应解析失败: %v", err)
		return nil
	}

	domainCDNMap := buildDomainCDNMap(collectQuakeDomains(serviceInfo.Data), cfg.SubdomainBruteForceThreads)
	var results []string
	for _, item := range serviceInfo.Data {
		if len(item.Service.HTTP.URL) == 0 {
			target := fmt.Sprintf("%s:%d", item.IP, item.Port)
			if utils.GetItemInArray(results, target) == -1 {
				emitOutput(state, ddout.OutputMessage{
					Type: "Quake",
					IP:   item.IP,
					Port: strconv.Itoa(item.Port),
					Show: target,
				})
				results = append(results, target)
			}
			continue
		}

		isCDN := domainCDNMap[item.Service.HTTP.Host]
		if !isCDN {
			addIPDomainMap(state, item.IP, item.Service.HTTP.Host)
		}

		if cfg.OnlyIPPort && !isCDN {
			target := fmt.Sprintf("%v://%v:%v", strings.ReplaceAll(item.Service.Name, "http/ssl", "https"), item.IP, item.Port)
			if utils.GetItemInArray(results, target) == -1 {
				results = append(results, target)
				emitOutput(state, ddout.OutputMessage{
					Type:     "Quake",
					IP:       item.IP,
					Port:     strconv.Itoa(item.Port),
					Protocol: item.Service.Name,
					Show:     target,
				})
			}
			continue
		}

		for _, target := range item.Service.HTTP.URL {
			if utils.GetItemInArray(results, target) == -1 && (!isCDN || cfg.AllowCDNAssets) {
				results = append(results, target)
				emitOutput(state, ddout.OutputMessage{
					Type:     "Quake",
					IP:       item.IP,
					Port:     strconv.Itoa(item.Port),
					Protocol: item.Service.Name,
					URI:      target,
					Show:     target,
				})
			}
		}
	}

	return results
}

func isQuakeVIP(apiConfigFile string) bool {
	keys, err := readAPIKeys(apiConfigFile, "quake")
	if err != nil {
		gologger.Error().Msgf("[Quake] 读取账户信息失败: %v", err)
		return false
	}

	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSpraying)
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://quake.360.net/api/v3/user/info", "")
	if err != nil {
		gologger.Error().Msg("[Quake] 用户信息请求构建失败")
		return false
	}
	req.Header.Set("X-QuakeToken", keys[rand.Intn(len(keys))])
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		gologger.Error().Msgf("[Quake] 用户信息查询失败: %v", err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		gologger.Error().Msg("[Quake] API-KEY错误")
		return false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		gologger.Error().Msgf("[Quake] 用户信息读取失败: %v", err)
		return false
	}

	return strings.Contains(string(body), "终身会员") || strings.Contains(string(body), "高级会员")
}

func readAPIKeys(path string, sourceName string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开 API Key 配置文件 %s 失败: %w", path, err)
	}
	defer f.Close()

	sourceAPIKeysMap := map[string][]string{}
	if err := yaml.NewDecoder(f).Decode(&sourceAPIKeysMap); err != nil {
		return nil, err
	}

	for _, source := range passive.AllSources {
		if strings.EqualFold(source.Name(), sourceName) {
			keys := sourceAPIKeysMap[strings.ToLower(source.Name())]
			if len(keys) == 0 {
				return nil, fmt.Errorf("%s API Key 为空", sourceName)
			}
			return keys, nil
		}
	}

	return nil, fmt.Errorf("未找到 %s API Key", sourceName)
}

func collectHunterDomains(items []hunterInfo) []string {
	var domains []string
	for _, item := range items {
		domains = append(domains, item.Domain)
	}
	return removeEmptyStrings(utils.RemoveDuplicateElement(domains))
}

func collectFOFADomains(results [][]string) []string {
	var domains []string
	for _, result := range results {
		if len(result) < 7 || result[6] == "" {
			continue
		}
		realHost := strings.ReplaceAll(result[0], result[1]+"://", "")
		domain := strings.ReplaceAll(realHost, ":"+result[5], "")
		domains = append(domains, domain)
	}
	return removeEmptyStrings(utils.RemoveDuplicateElement(domains))
}

func collectQuakeDomains(results []struct {
	Service struct {
		HTTP struct {
			Host  string   `json:"host"`
			Title string   `json:"title"`
			URL   []string `json:"http_load_url"`
		} `json:"http"`
		Name string `json:"name"`
	} `json:"service"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}) []string {
	var domains []string
	for _, result := range results {
		domains = append(domains, result.Service.HTTP.Host)
	}
	return removeEmptyStrings(utils.RemoveDuplicateElement(domains))
}

func buildDomainCDNMap(domains []string, threads int) map[string]bool {
	result := make(map[string]bool, len(domains))
	if len(domains) == 0 {
		return result
	}

	gologger.Info().Msgf("正在查询 [%v] 个域名是否为CDN资产", len(domains))
	cdnDomains, normalDomains, _ := cdn.CheckCDNs(domains, threads)
	for _, domain := range cdnDomains {
		result[domain] = true
	}
	for _, domain := range normalDomains {
		if _, ok := result[domain]; !ok {
			result[domain] = false
		}
	}
	return result
}

func addIPDomainMap(state *State, ip string, domain string) {
	if state == nil || state.IPDomainMap == nil || ip == "" || domain == "" {
		return
	}

	if state.IPDomainMapLock != nil {
		state.IPDomainMapLock.Lock()
		defer state.IPDomainMapLock.Unlock()
	}

	existing := state.IPDomainMap[ip]
	for _, item := range existing {
		if item == domain {
			return
		}
	}
	state.IPDomainMap[ip] = append(existing, domain)
}

func storeHunterWeb(state *State, item hunterInfo) {
	if state == nil || state.URLMap == nil {
		return
	}

	rootURL := fmt.Sprintf("%s://%s:%d", item.Protocol, item.IP, item.Port)
	responseCode, header, body, server, contentType, contentLen := utils.ExtractResponse(item.Banner)
	bodyHash := hashes.Md5([]byte(body))
	headerHash := hashes.Md5([]byte(header))

	if state.BodyHMap != nil {
		_ = state.BodyHMap.Set(bodyHash, []byte(body))
	}
	if state.HeaderHMap != nil {
		_ = state.HeaderHMap.Set(headerHash, []byte(header))
	}

	length, _ := strconv.Atoi(contentLen)
	statusCode, _ := strconv.Atoi(responseCode)

	webPath := structs.UrlPathEntity{
		Hash:             bodyHash,
		Title:            item.Title,
		StatusCode:       statusCode,
		ContentType:      contentType,
		Server:           server,
		ContentLength:    length,
		HeaderHashString: headerHash,
	}

	if state.URLMapLock != nil {
		state.URLMapLock.Lock()
		defer state.URLMapLock.Unlock()
	}
	if _, ok := state.URLMap[rootURL]; ok {
		return
	}

	state.URLMap[rootURL] = structs.URLEntity{
		IP:   item.IP,
		Port: item.Port,
		WebPaths: map[string]structs.UrlPathEntity{
			"/": webPath,
		},
	}
}

func storeHunterService(state *State, item hunterInfo) {
	if state == nil || state.IPPortMap == nil {
		return
	}

	hostPort := fmt.Sprintf("%s:%d", item.IP, item.Port)
	if state.IPPortMapLock != nil {
		state.IPPortMapLock.Lock()
		defer state.IPPortMapLock.Unlock()
	}
	if _, ok := state.IPPortMap[hostPort]; ok {
		return
	}
	if state.BannerHMap != nil {
		_ = state.BannerHMap.Set(hostPort, []byte(item.Banner))
	}
	state.IPPortMap[hostPort] = item.Protocol
}

func buildFOFATarget(host string, protocol string, ip string, port string, domain string, title string, icp string, isCDN bool, cfg Config) (string, string) {
	show := "[Fofa]"
	addTarget := ""
	if cfg.OnlyIPPort && !isCDN {
		addTarget = protocol + "://" + ip + ":" + port
		show += " " + addTarget
	} else {
		switch protocol {
		case "http":
			addTarget = protocol + "://" + host
			show += " " + addTarget
		case "https":
			addTarget = host
			show += " " + host
		default:
			addTarget = host
			show += " " + protocol + "://" + host
		}
	}
	if title != "" {
		show += " [" + title + "]"
	}
	if icp != "" {
		show += " [" + icp + "]"
	}
	if isCDN {
		show += " [CDN]"
	}
	return addTarget, show
}

func removeEmptyStrings(input []string) []string {
	if len(input) == 0 {
		return nil
	}
	result := make([]string, 0, len(input))
	for _, item := range input {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		result = append(result, item)
	}
	return result
}
