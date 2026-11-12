// Package web Web 探测相关模块。
package web

import (
	"fmt"
	"github.com/TokEat/argus/scanner/ddout"
	"github.com/TokEat/argus/scanner/lib/ddfinger"
	"github.com/TokEat/argus/scanner/structs"
	"github.com/TokEat/argus/scanner/utils"
	"net"
	"net/url"
	"sort"
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
	DirEvidenceResultMap   map[string][]string
	DirEvidenceResultMapMu *sync.Mutex
	// CDNHosts holds lowercased hostnames classified as CDN so emitted Web /
	// Domain-Bind messages can carry the "cdn" asset tag.
	CDNHosts map[string]struct{}

	// ReportAllDirProbes emits a Dir-Probe result for every directory probe
	// response, including misses. Used by MCP/Agent dir debug so callers see
	// per-path status and body instead of only fingerprint matches.
	ReportAllDirProbes bool

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
		DirEvidenceResultMap:   make(map[string][]string),
		DirEvidenceResultMapMu: &sync.Mutex{},
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

	_, inserted := rt.upsertResponse(resp, true)
	if !inserted {
		return
	}

	if rt.emit != nil && isHTTPScheme(resp.URL) {
		rt.emit(structs.OutputMessage{
			Type: "Web",
			Web: structs.WebInfo{
				Status:   strconv.Itoa(resp.StatusCode),
				Title:    resp.Title,
				Cert:     compactCertificate(resp),
				Size:     strconv.Itoa(resp.ContentLength),
				Redirect: webRedirect(resp),
			},
			URI:    resp.URL,
			Finger: rt.matchAllFingers(resp),
			Tag:    rt.assetTag(resp.URL),
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

	matched := make([]string, 0, 2)
	catchAll := rt.isHomepageCatchAll(resp)
	for _, path := range rt.matchingDirPaths(resp.Path) {
		for _, productName := range rt.DirDB[path] {
			success := !catchAll && rt.matchesProduct(resp, productName)

			if success {
				rootURL, _ := rt.upsertResponse(resp, false)
				rt.emit(ddout.OutputMessage{
					Type: "Active-Finger",
					Web: structs.WebInfo{
						Status: strconv.Itoa(resp.StatusCode),
						Title:  resp.Title,
					},
					Finger:        []string{productName},
					URI:           resp.URL,
					AdditionalMsg: "[directory-probe]",
				})
				if rootURL != "" {
					rt.addDirEvidence(rootURL+normalizedPath(resp), productName)
				}
				matched = append(matched, productName)
				continue
			}

			if catchAll || resp.StatusCode != 200 {
				continue
			}
			workflowEntity, ok := rt.WorkFlowDB[productName]
			if !ok || !workflowEntity.DirFallback {
				continue
			}

			rootURL, _ := rt.upsertResponse(resp, false)
			if rootURL == "" {
				continue
			}

			rt.emit(ddout.OutputMessage{
				Type: "Active-Finger",
				Web: structs.WebInfo{
					Status: strconv.Itoa(resp.StatusCode),
					Title:  resp.Title,
				},
				Finger:        []string{productName},
				URI:           resp.URL,
				AdditionalMsg: "[dir-fallback]",
			})
			matched = append(matched, productName)

			rt.addDirFallback(rootURL, productName)
		}
	}
	rt.emitDirProbe(resp, matched)
}

func (rt *Runtime) emitDirProbe(resp runner.Result, matched []string) {
	if rt == nil || !rt.ReportAllDirProbes || rt.emit == nil {
		return
	}
	body := resp.Body
	const maxBody = 2048
	if len(body) > maxBody {
		body = body[:maxBody]
	}
	rt.emit(structs.OutputMessage{
		Type: "Dir-Probe",
		Web: structs.WebInfo{
			Status: strconv.Itoa(resp.StatusCode),
			Title:  resp.Title,
			Size:   strconv.Itoa(resp.ContentLength),
		},
		URI:           resp.URL,
		Finger:        matched,
		AdditionalMsg: body,
	})
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
			Tag:           rt.assetTag(resp.URL),
		})
	}

	rt.upsertResponse(resp, true)
}

// assetTag returns the special asset class for a probed URL, currently "cdn"
// when its hostname was classified as a CDN domain during CDN checks.
func (rt *Runtime) assetTag(rawURL string) string {
	if rt == nil || len(rt.CDNHosts) == 0 {
		return ""
	}
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	if _, ok := rt.CDNHosts[strings.ToLower(parsed.Hostname())]; ok {
		return "cdn"
	}
	return ""
}

// isHomepageCatchAll reports a directory probe that returned the same page as
// the already-recorded site root. Catch-all auth gates and SPA/history fallback
// pages share that signature and must not fan out into product fingerprints.
func (rt *Runtime) isHomepageCatchAll(resp runner.Result) bool {
	if rt == nil {
		return false
	}
	hash := hashValue(resp, "body_md5")
	if hash == "" {
		return false
	}
	parsed, err := url.Parse(responseURL(resp))
	if err != nil {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	rootURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	path := normalizedPath(resp)
	if path == "/" {
		return false
	}

	rt.lockURLMap()
	defer rt.unlockURLMap()
	entry, ok := rt.URLMap[rootURL]
	if !ok || entry.WebPaths == nil {
		return false
	}
	home, ok := entry.WebPaths["/"]
	if !ok || home.Hash == "" || home.Hash != hash {
		return false
	}
	if home.StatusCode != 0 && home.StatusCode != resp.StatusCode {
		return false
	}
	return true
}

func (rt *Runtime) matchingDirPaths(respPath string) []string {
	var paths []string
	for dbPath := range rt.DirDB {
		if respPath == dbPath {
			paths = append(paths, dbPath)
		}
	}
	sort.Strings(paths)
	return paths
}

func (rt *Runtime) matchAllFingers(resp runner.Result) []string {
	if rt == nil || len(rt.FingerprintDB) == 0 {
		return nil
	}
	portInt, err := strconv.Atoi(resp.Port)
	if err != nil {
		portInt = -1
	}
	cert := getTLSString(resp)
	path := normalizedPath(resp)
	bodyHash := hashValue(resp, "body_md5")
	seen := map[string]struct{}{}
	var results []string

	ctx := ddfinger.NewCheckContext(
		resp.Scheme,
		resp.Header,
		resp.Body,
		resp.WebServer,
		resp.Title,
		cert,
		portInt,
		path,
		bodyHash,
		resp.FavIconMMH3,
		resp.StatusCode,
		resp.ContentType,
		"",
	)

	for _, finger := range rt.FingerprintDB {
		if _, ok := seen[finger.ProductName]; ok {
			continue
		}
		if !ddfinger.SingleCheckWithContext(finger, ctx) {
			continue
		}
		seen[finger.ProductName] = struct{}{}
		results = append(results, finger.ProductName)
	}
	return results
}

func (rt *Runtime) matchesProduct(resp runner.Result, productName string) bool {
	portInt, err := strconv.Atoi(resp.Port)
	if err != nil {
		portInt = -1
	}

	ctx := ddfinger.NewCheckContext(
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
	)

	for _, finger := range rt.fingerprintByProduct[productName] {
		if ddfinger.DirProbeCheckWithContext(finger, ctx) {
			return true
		}
	}

	return false
}

func (rt *Runtime) upsertResponse(resp runner.Result, natural bool) (string, bool) {
	finalURL := responseURL(resp)
	URL, err := url.Parse(finalURL)
	if err != nil {
		return "", false
	}
	if URL.Scheme != "http" && URL.Scheme != "https" {
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
		Natural:          natural,
	}

	port := responsePort(URL, resp.Port)

	rt.lockURLMap()
	defer rt.unlockURLMap()

	if urlEntry, ok := rt.URLMap[rootURL]; ok {
		if urlEntry.WebPaths == nil {
			urlEntry.WebPaths = make(map[string]structs.UrlPathEntity)
		}
		if existingPath, pathOK := urlEntry.WebPaths[path]; pathOK {
			pathEntity.Natural = existingPath.Natural || natural
			if shouldReplaceWebPath(existingPath, pathEntity) {
				urlEntry.WebPaths[path] = pathEntity
				rt.URLMap[rootURL] = urlEntry
				return rootURL, true
			}
			if pathEntity.Natural != existingPath.Natural {
				existingPath.Natural = pathEntity.Natural
				urlEntry.WebPaths[path] = existingPath
				rt.URLMap[rootURL] = urlEntry
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
	appendUniqueProduct(&rt.DirFallbackResultMap, rt.DirFallbackResultMapMu, rootURL, productName)
}

func (rt *Runtime) addDirEvidence(fullURL string, productName string) {
	appendUniqueProduct(&rt.DirEvidenceResultMap, rt.DirEvidenceResultMapMu, fullURL, productName)
}

func appendUniqueProduct(dst *map[string][]string, mu *sync.Mutex, key, productName string) {
	if dst == nil || key == "" || productName == "" {
		return
	}
	if mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}
	if *dst == nil {
		*dst = make(map[string][]string)
	}
	existing := (*dst)[key]
	if utils.GetItemInArray(existing, productName) != -1 {
		return
	}
	(*dst)[key] = append(existing, productName)
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

func isHTTPScheme(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		return true
	default:
		return false
	}
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

func webRedirect(resp runner.Result) string {
	location := strings.TrimSpace(resp.Location)
	if location != "" {
		return location
	}
	finalURL := strings.TrimSpace(resp.FinalURL)
	if finalURL != "" && finalURL != strings.TrimSpace(resp.URL) {
		return finalURL
	}
	return ""
}

// ProbeURLs builds HTTP(S) probe targets from a protocol-identify result.
// TLS-typical ports that were labeled http still get an https:// attempt so
// the WEB block can show the leaf certificate.
func ProbeURLs(hostPort, service string) []string {
	hostPort = strings.TrimSpace(hostPort)
	service = strings.ToLower(strings.TrimSpace(service))
	if hostPort == "" {
		return nil
	}
	switch service {
	case "https", "ssl/http", "http2":
		return []string{"https://" + hostPort}
	case "http", "http-proxy", "http-alt":
		urls := []string{"http://" + hostPort}
		if tlsLikelyWebPort(hostPort) {
			urls = append(urls, "https://"+hostPort)
		}
		return urls
	default:
		return nil
	}
}

func tlsLikelyWebPort(hostPort string) bool {
	_, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return false
	}
	return TLSLikelyPort(port)
}

// TLSLikelyPort reports whether the given port number commonly serves HTTPS
// directly, so domain-form probing can pick the scheme without protocol
// identification.
func TLSLikelyPort(port string) bool {
	switch port {
	case "443", "1443", "3443", "4443", "6443", "7443", "8443", "9443", "10443":
		return true
	default:
		return false
	}
}

func compactCertificate(resp runner.Result) string {
	if resp.TLSData == nil || resp.TLSData.CertificateResponse == nil {
		return ""
	}
	cert := resp.TLSData.CertificateResponse
	parts := make([]string, 0, 6)
	cn := strings.TrimSpace(cert.SubjectCN)
	if cn == "" && len(cert.SubjectAN) > 0 {
		cn = strings.TrimSpace(cert.SubjectAN[0])
	}
	if cn != "" {
		parts = append(parts, "CN="+cn)
	}
	if sans := compactSAN(cert.SubjectAN, cn); sans != "" {
		parts = append(parts, "SAN="+sans)
	}
	issuer := strings.TrimSpace(cert.IssuerCN)
	if issuer == "" && len(cert.IssuerOrg) > 0 {
		issuer = strings.TrimSpace(cert.IssuerOrg[0])
	}
	if issuer != "" {
		parts = append(parts, "issuer="+issuer)
	}
	if cert.SelfSigned {
		parts = append(parts, "self_signed=true")
	}
	if cert.Expired {
		parts = append(parts, "expired=true")
	}
	if cert.MisMatched {
		parts = append(parts, "mismatch=true")
	}
	out := strings.Join(parts, " ")
	if len(out) > 160 {
		return out[:160]
	}
	return out
}

func compactSAN(names []string, cn string) string {
	var out []string
	seen := map[string]struct{}{}
	if cn != "" {
		seen[cn] = struct{}{}
	}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
		if len(out) == 3 {
			break
		}
	}
	return strings.Join(out, ",")
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
