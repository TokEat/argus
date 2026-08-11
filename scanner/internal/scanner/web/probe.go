// Package web Web 探测相关模块。
package web

import (
	"fmt"
	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/lib/ddfinger"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
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
	emit                 func(structs.OutputMessage)
	redirectMu           sync.Mutex
	redirectURLSet       map[string]struct{}
	redirectURLs         []string
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
	emit func(structs.OutputMessage),
) *Runtime {
	if emit == nil {
		emit = func(msg structs.OutputMessage) {
			ddout.FormatOutput(msg)
		}
	}
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
		emit:                   emit,
		fingerprintByProduct:   make(map[string][]structs.FingerPEntity),
		redirectURLSet:         make(map[string]struct{}),
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

	rt.collectRedirectLocation(resp)

	_, inserted := rt.upsertResponse(resp)
	if !inserted {
		return
	}

	if rt.emit != nil {
		rt.emit(structs.OutputMessage{
			Type: "Web",
			Web: structs.WebInfo{
				Status: strconv.Itoa(resp.StatusCode),
				Title:  resp.Title,
			},
			URI:    resp.URL,
			Finger: nil,
		})
	}
}

// DrainRedirectURLs returns same-origin redirect locations discovered during
// HTTP probing and clears the queue for the next bounded follow-up pass.
func (rt *Runtime) DrainRedirectURLs() []string {
	if rt == nil {
		return nil
	}

	rt.redirectMu.Lock()
	defer rt.redirectMu.Unlock()

	if len(rt.redirectURLs) == 0 {
		return nil
	}
	urls := append([]string(nil), rt.redirectURLs...)
	rt.redirectURLs = nil
	return utils.RemoveDuplicateElement(urls)
}

// DirBruteCallback 目录爆破回调。
func (rt *Runtime) DirBruteCallback(resp runner.Result) {
	if rt == nil {
		return
	}

	for _, path := range rt.matchingDirPaths(resp.Path) {
		for _, productName := range rt.DirDB[path] {
			success := rt.matchesProduct(resp, productName)

			if success {
				rt.upsertResponse(resp)
				rt.emit(ddout.OutputMessage{
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

			rootURL, _ := rt.upsertResponse(resp)
			if rootURL == "" {
				continue
			}

			rt.emit(ddout.OutputMessage{
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
	gologger.Info().Msgf("[HostBind] 域名绑定探测目标数=%d (URLMap=%d, IPDomainMap=%d)", len(urls), len(rt.URLMap), len(rt.IPDomainMap))
	if len(urls) > 0 {
		httpx.DirBrute(urls, rt.HostBindCallback, httpProxy, webThreads, webTimeout)
	}
	gologger.AuditTimeLogger("域名绑定资产发现结束")
}

// HostBindCallback 域名绑定探测回调。
func (rt *Runtime) HostBindCallback(resp runner.Result) {
	if rt == nil || !rt.isNewHostBind(resp) {
		return
	}

	if rt.emit != nil {
		rt.emit(structs.OutputMessage{
			Type: "Domain-Bind",
			Web: structs.WebInfo{
				Status: strconv.Itoa(resp.StatusCode),
			},
			URI:           resp.URL,
			AdditionalMsg: resp.Title,
		})
	}

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

	port := responsePort(URL, resp.Port)

	rt.lockURLMap()
	defer rt.unlockURLMap()

	if urlEntry, ok := rt.URLMap[rootURL]; ok {
		if urlEntry.WebPaths == nil {
			urlEntry.WebPaths = make(map[string]structs.UrlPathEntity)
		}
		if existingPath, pathOK := urlEntry.WebPaths[path]; pathOK {
			if shouldReplaceWebPath(existingPath, pathEntity) {
				urlEntry.WebPaths[path] = pathEntity
				rt.URLMap[rootURL] = urlEntry
				return rootURL, true
			}
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

func shouldReplaceWebPath(existing, next structs.UrlPathEntity) bool {
	if next.Hash == "" && next.StatusCode == 0 && next.ContentLength == 0 {
		return false
	}
	if existing.Hash == "" && next.Hash != "" {
		return true
	}
	if existing.StatusCode == 0 && next.StatusCode != 0 {
		return true
	}
	if existing.ContentLength == 0 && next.ContentLength > 0 {
		return true
	}
	return existing.StatusCode >= 300 && existing.StatusCode < 400 && next.StatusCode >= 200 && next.StatusCode < 300
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

func (rt *Runtime) collectRedirectLocation(resp runner.Result) {
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return
	}

	redirectURL, ok := sameOriginRedirectURL(resp)
	if !ok {
		return
	}

	rt.redirectMu.Lock()
	defer rt.redirectMu.Unlock()

	if _, exists := rt.redirectURLSet[redirectURL]; exists {
		return
	}
	rt.redirectURLSet[redirectURL] = struct{}{}
	rt.redirectURLs = append(rt.redirectURLs, redirectURL)
}

func sameOriginRedirectURL(resp runner.Result) (string, bool) {
	location := strings.TrimSpace(resp.Location)
	if location == "" {
		return "", false
	}

	baseRaw := responseURL(resp)
	if baseRaw == "" {
		baseRaw = resp.URL
	}
	baseURL, err := url.Parse(baseRaw)
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" {
		return "", false
	}

	locationURL, err := url.Parse(location)
	if err != nil {
		return "", false
	}
	redirectURL := baseURL.ResolveReference(locationURL)
	if redirectURL.Scheme != "http" && redirectURL.Scheme != "https" {
		return "", false
	}
	if !sameOriginHost(baseURL, redirectURL) {
		return "", false
	}
	redirectURL.Fragment = ""

	normalized := redirectURL.String()
	if normalized == baseURL.String() || normalized == resp.URL || normalized == resp.FinalURL {
		return "", false
	}
	return normalized, true
}

func sameOriginHost(baseURL, redirectURL *url.URL) bool {
	if baseURL == nil || redirectURL == nil {
		return false
	}
	if !strings.EqualFold(baseURL.Hostname(), redirectURL.Hostname()) {
		return false
	}
	if strings.EqualFold(baseURL.Scheme, redirectURL.Scheme) && effectivePort(baseURL) == effectivePort(redirectURL) {
		return true
	}
	return isDefaultHTTPToHTTPSUpgrade(baseURL, redirectURL)
}

func responsePort(URL *url.URL, fallback string) int {
	port := effectivePort(URL)
	if port == "" {
		port = fallback
	}
	value, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return value
}

func effectivePort(URL *url.URL) string {
	if URL == nil {
		return ""
	}
	if port := URL.Port(); port != "" {
		return port
	}
	switch URL.Scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func isDefaultHTTPToHTTPSUpgrade(baseURL, redirectURL *url.URL) bool {
	if baseURL == nil || redirectURL == nil {
		return false
	}
	return baseURL.Scheme == "http" &&
		redirectURL.Scheme == "https" &&
		isDefaultPort(baseURL) &&
		isDefaultPort(redirectURL)
}

func isDefaultPort(URL *url.URL) bool {
	if URL == nil {
		return false
	}
	port := URL.Port()
	return port == "" ||
		(URL.Scheme == "http" && port == "80") ||
		(URL.Scheme == "https" && port == "443")
}

func responseURL(resp runner.Result) string {
	if resp.FinalURL != "" {
		return resp.FinalURL
	}
	return resp.URL
}

func normalizedPath(resp runner.Result) string {
	if resp.FinalURL != "" {
		if URL, err := url.Parse(resp.FinalURL); err == nil {
			if URL.Path != "" {
				return URL.Path
			}
		}
	}

	path := resp.Path
	if path == "" {
		if URL, err := url.Parse(responseURL(resp)); err == nil {
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
