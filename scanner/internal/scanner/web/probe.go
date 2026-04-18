// Package web Web 探测相关模块。
package web

import (
	"dddd/scanner/ddout"
	"dddd/scanner/lib/ddfinger"
	"dddd/scanner/structs"
	"dddd/scanner/utils"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/httpx"
	"github.com/projectdiscovery/httpx/runner"
)

// Runtime holds the mutable state needed by the web probing stages without
// reaching into package-level globals.
type Runtime struct {
	URLMap                 map[string]structs.URLEntity
	URLMapLock             *sync.Mutex
	IPDomainMap            map[string][]string
	BodyHMap               *hybrid.HybridMap
	HeaderHMap             *hybrid.HybridMap
	DirDB                  map[string][]string
	FingerprintDB          []structs.FingerPEntity
	WorkFlowDB             map[string]structs.WorkFlowEntity
	DirFallbackResultMap   map[string][]string
	DirFallbackResultMapMu *sync.Mutex

	fingerprintByProduct map[string][]structs.FingerPEntity
}

func NewRuntime(
	urlMap map[string]structs.URLEntity,
	urlMapLock *sync.Mutex,
	ipDomainMap map[string][]string,
	bodyHMap *hybrid.HybridMap,
	headerHMap *hybrid.HybridMap,
	dirDB map[string][]string,
	fingerprintDB []structs.FingerPEntity,
	workFlowDB map[string]structs.WorkFlowEntity,
	dirFallbackResultMap map[string][]string,
	dirFallbackResultMapMu *sync.Mutex,
) *Runtime {
	runtime := &Runtime{
		URLMap:                 urlMap,
		URLMapLock:             urlMapLock,
		IPDomainMap:            ipDomainMap,
		BodyHMap:               bodyHMap,
		HeaderHMap:             headerHMap,
		DirDB:                  dirDB,
		FingerprintDB:          fingerprintDB,
		WorkFlowDB:             workFlowDB,
		DirFallbackResultMap:   dirFallbackResultMap,
		DirFallbackResultMapMu: dirFallbackResultMapMu,
		fingerprintByProduct:   make(map[string][]structs.FingerPEntity),
	}

	for _, finger := range fingerprintDB {
		runtime.fingerprintByProduct[finger.ProductName] = append(runtime.fingerprintByProduct[finger.ProductName], finger)
	}

	return runtime
}

// URLCallback HTTP 响应回调。
func (rt *Runtime) URLCallback(resp runner.Result) {
	if rt == nil {
		return
	}

	_, inserted := rt.upsertResponse(resp)
	if !inserted {
		return
	}

	ddout.FormatOutput(ddout.OutputMessage{
		Type: "Web",
		URI:  resp.URL,
		Web: ddout.WebInfo{
			Status: strconv.Itoa(resp.StatusCode),
			Title:  resp.Title,
		},
	})
}

// DirBruteCallback 目录爆破回调。
func (rt *Runtime) DirBruteCallback(resp runner.Result) {
	if rt == nil {
		return
	}

	for _, path := range rt.matchingDirPaths(resp.Path) {
		for _, productName := range rt.DirDB[path] {
			success := rt.matchesProduct(resp, productName)
			rootURL, _ := rt.upsertResponse(resp)

			if success {
				ddout.FormatOutput(ddout.OutputMessage{
					Type:   "Active-Finger",
					Finger: []string{productName},
					URI:    resp.URL,
				})
				continue
			}

			if resp.StatusCode != 200 {
				continue
			}
			workflowEntity, ok := rt.WorkFlowDB[productName]
			if !ok || !workflowEntity.DirFallback {
				continue
			}

			ddout.FormatOutput(ddout.OutputMessage{
				Type:          "Active-Finger",
				Finger:        []string{productName},
				URI:           resp.URL,
				AdditionalMsg: "[dir-fallback]",
			})
			rt.addDirFallback(rootURL, productName)
		}
	}
}

// HostBindCheck 域名绑定资产探测。
func (rt *Runtime) HostBindCheck(httpProxy string, webThreads int, webTimeout int) {
	if rt == nil {
		return
	}

	gologger.Info().Msg("域名绑定资产发现")

	var urls []string
	rt.lockURLMap()
	for rootURL := range rt.URLMap {
		URL, err := url.Parse(rootURL)
		if err != nil {
			continue
		}

		if strings.Contains(URL.Host, ":") {
			tmp := strings.Split(URL.Host, ":")
			if len(tmp) != 2 {
				continue
			}
			ip, port := tmp[0], tmp[1]
			if !utils.IsIPv4(ip) {
				continue
			}
			domains, ok := rt.IPDomainMap[ip]
			if !ok {
				continue
			}
			for _, domain := range domains {
				urls = append(urls, fmt.Sprintf("%v://%v:%v", URL.Scheme, domain, port))
			}
		} else {
			ip := URL.Host
			if !utils.IsIPv4(ip) {
				continue
			}
			domains, ok := rt.IPDomainMap[ip]
			if !ok {
				continue
			}
			for _, domain := range domains {
				urls = append(urls, fmt.Sprintf("%v://%v", URL.Scheme, domain))
			}
		}
	}
	rt.unlockURLMap()

	urls = utils.RemoveDuplicateElement(urls)
	httpx.DirBrute(urls, rt.HostBindCallback, httpProxy, webThreads, webTimeout)
	gologger.AuditTimeLogger("域名绑定资产发现结束")
}

// HostBindCallback 域名绑定探测回调。
func (rt *Runtime) HostBindCallback(resp runner.Result) {
	if rt == nil || !rt.isNewHostBind(resp) {
		return
	}

	ddout.FormatOutput(ddout.OutputMessage{
		Type: "Domain-Bind",
		Web: ddout.WebInfo{
			Status: strconv.Itoa(resp.StatusCode),
		},
		URI:           resp.URL,
		AdditionalMsg: resp.Title,
	})

	rt.upsertResponse(resp)
}

func (rt *Runtime) matchingDirPaths(respPath string) []string {
	var paths []string
	for dbPath := range rt.DirDB {
		if strings.HasSuffix(respPath, dbPath) {
			paths = append(paths, dbPath)
		}
	}
	return paths
}

func (rt *Runtime) matchesProduct(resp runner.Result, productName string) bool {
	portInt, err := strconv.Atoi(resp.Port)
	if err != nil {
		portInt = -1
	}

	for _, finger := range rt.fingerprintByProduct[productName] {
		if ddfinger.SingleCheck(
			finger,
			resp.Scheme,
			resp.Header,
			resp.Body,
			resp.WebServer,
			resp.Title,
			getTLSString(resp),
			portInt,
			normalizedPath(resp),
			hashValue(resp, "body_md5"),
			resp.FavIconMMH3,
			resp.StatusCode,
			resp.ContentType,
			"",
		) {
			return true
		}
	}

	return false
}

func (rt *Runtime) upsertResponse(resp runner.Result) (string, bool) {
	finalURL := responseURL(resp)
	URL, err := url.Parse(finalURL)
	if err != nil {
		return "", false
	}

	path := normalizedPath(resp)
	rootURL := fmt.Sprintf("%s://%s", URL.Scheme, URL.Host)
	bodyHash := hashValue(resp, "body_md5")
	headerHash := hashValue(resp, "header_md5")

	if bodyHash != "" && rt.BodyHMap != nil {
		_ = rt.BodyHMap.Set(bodyHash, []byte(resp.Body))
	}
	if headerHash != "" && rt.HeaderHMap != nil {
		_ = rt.HeaderHMap.Set(headerHash, []byte(resp.Header))
	}

	pathEntity := structs.UrlPathEntity{
		Hash:             bodyHash,
		Title:            resp.Title,
		StatusCode:       resp.StatusCode,
		ContentType:      resp.ContentType,
		Server:           resp.WebServer,
		ContentLength:    resp.ContentLength,
		HeaderHashString: headerHash,
		IconHash:         resp.FavIconMMH3,
	}

	port, err := strconv.Atoi(resp.Port)
	if err != nil {
		port = 0
	}

	rt.lockURLMap()
	defer rt.unlockURLMap()

	if urlEntry, ok := rt.URLMap[rootURL]; ok {
		if urlEntry.WebPaths == nil {
			urlEntry.WebPaths = make(map[string]structs.UrlPathEntity)
		}
		if _, pathOK := urlEntry.WebPaths[path]; pathOK {
			return rootURL, false
		}
		urlEntry.WebPaths[path] = pathEntity
		rt.URLMap[rootURL] = urlEntry
		return rootURL, true
	}

	rt.URLMap[rootURL] = structs.URLEntity{
		IP:       resp.Host,
		Port:     port,
		WebPaths: map[string]structs.UrlPathEntity{path: pathEntity},
		Cert:     getTLSString(resp),
	}
	return rootURL, true
}

func (rt *Runtime) isNewHostBind(resp runner.Result) bool {
	bodyHash := hashValue(resp, "body_md5")
	path := normalizedPath(resp)

	rt.lockURLMap()
	defer rt.unlockURLMap()

	for _, ip := range resp.A {
		for rootURL, urlEntry := range rt.URLMap {
			URL, err := url.Parse(rootURL)
			if err != nil {
				continue
			}
			if URL.Scheme != resp.Scheme {
				continue
			}
			if urlEntry.IP != ip {
				continue
			}
			if strconv.Itoa(urlEntry.Port) != resp.Port {
				continue
			}

			existingPath, ok := urlEntry.WebPaths[path]
			if !ok {
				continue
			}

			if existingPath.StatusCode != resp.StatusCode || existingPath.Hash != bodyHash {
				return true
			}
		}
	}

	return false
}

func (rt *Runtime) addDirFallback(rootURL string, productName string) {
	if rt.DirFallbackResultMap == nil {
		return
	}

	if rt.DirFallbackResultMapMu != nil {
		rt.DirFallbackResultMapMu.Lock()
		defer rt.DirFallbackResultMapMu.Unlock()
	}

	existing := rt.DirFallbackResultMap[rootURL]
	if utils.GetItemInArray(existing, productName) != -1 {
		return
	}
	rt.DirFallbackResultMap[rootURL] = append(existing, productName)
}

func (rt *Runtime) lockURLMap() {
	if rt.URLMapLock != nil {
		rt.URLMapLock.Lock()
	}
}

func (rt *Runtime) unlockURLMap() {
	if rt.URLMapLock != nil {
		rt.URLMapLock.Unlock()
	}
}

func responseURL(resp runner.Result) string {
	if resp.FinalURL != "" {
		return resp.FinalURL
	}
	return resp.URL
}

func normalizedPath(resp runner.Result) string {
	path := resp.Path
	if path == "" {
		URL, err := url.Parse(responseURL(resp))
		if err == nil {
			path = URL.Path
		}
	}
	if path == "" {
		path = "/"
	}
	return path
}

func hashValue(resp runner.Result, key string) string {
	if resp.Hashes == nil {
		return ""
	}
	value, ok := resp.Hashes[key]
	if !ok || value == nil {
		return ""
	}
	if typed, ok := value.(string); ok {
		return typed
	}
	return fmt.Sprint(value)
}

func getTLSString(resp runner.Result) string {
	if resp.TLSData == nil {
		return ""
	}

	result := ""
	result += "SubjectCN: " + resp.TLSData.SubjectCN + "\n"
	result += "SubjectDN: " + resp.TLSData.SubjectDN + "\n"
	result += "IssuerCN: " + resp.TLSData.IssuerCN + "\n"
	result += "IssuerDN: " + resp.TLSData.IssuerDN + "\n"
	result += "IssuerOrg: \n"
	for _, v := range resp.TLSData.IssuerOrg {
		result += "    - " + v + "\n"
	}

	return result
}
