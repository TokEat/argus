// Package finger 指纹识别引擎。
package finger

import (
	"dddd/scanner/ddout"
	"dddd/scanner/lib/ddfinger"
	"dddd/scanner/structs"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
)

// Runtime holds the state required by the fingerprint identification stage.
type Runtime struct {
	IPPortMap     map[string]string
	URLMap        map[string]structs.URLEntity
	ResultMap     map[string][]string
	BannerHMap    *hybrid.HybridMap
	BodyHMap      *hybrid.HybridMap
	HeaderHMap    *hybrid.HybridMap
	FingerprintDB []structs.FingerPEntity
}

func NewRuntime(
	ipPortMap map[string]string,
	urlMap map[string]structs.URLEntity,
	resultMap map[string][]string,
	bannerHMap *hybrid.HybridMap,
	bodyHMap *hybrid.HybridMap,
	headerHMap *hybrid.HybridMap,
	fingerprintDB []structs.FingerPEntity,
) *Runtime {
	return &Runtime{
		IPPortMap:     ipPortMap,
		URLMap:        urlMap,
		ResultMap:     resultMap,
		BannerHMap:    bannerHMap,
		BodyHMap:      bodyHMap,
		HeaderHMap:    headerHMap,
		FingerprintDB: fingerprintDB,
	}
}

// Identify executes fingerprint identification against the provided runtime state.
func (rt *Runtime) Identify() {
	if rt == nil {
		return
	}

	gologger.Info().Msg("指纹识别中")

	rt.identifyServices()
	rt.identifyWeb()

	gologger.AuditTimeLogger("指纹识别结束")
}

func (rt *Runtime) identifyServices() {
	for hostPort, protocol := range rt.IPPortMap {
		if protocol == "http" || protocol == "https" || protocol == "" {
			continue
		}

		parts := splitHostPort(hostPort)
		if len(parts) != 2 {
			continue
		}
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}

		results := rt.checkPath("no#web", structs.UrlPathEntity{}, port, protocol, rt.banner(hostPort), "")
		if len(results) == 0 {
			continue
		}

		uri := fmt.Sprintf("%s://%s", protocol, hostPort)
		rt.ResultMap[uri] = results
		ddout.FormatOutput(ddout.OutputMessage{
			Type:   "Finger",
			Finger: results,
			URI:    uri,
		})
	}
}

func (rt *Runtime) identifyWeb() {
	for rootURL, urlEntity := range rt.URLMap {
		scheme := ""
		if parsed, err := url.Parse(rootURL); err == nil {
			scheme = parsed.Scheme
		}

		banner := ""
		if urlEntity.IP != "" {
			banner = rt.banner(fmt.Sprintf("%s:%d", urlEntity.IP, urlEntity.Port))
		}

		for path, pathEntity := range urlEntity.WebPaths {
			results := rt.checkPath(path, pathEntity, urlEntity.Port, scheme, banner, urlEntity.Cert)
			fullURL := rootURL + path

			if len(results) == 0 {
				rt.ResultMap[fullURL] = []string{}
				continue
			}

			rt.ResultMap[fullURL] = results
			ddout.FormatOutput(ddout.OutputMessage{
				Type: "Finger",
				Web: ddout.WebInfo{
					Status: strconv.Itoa(pathEntity.StatusCode),
					Title:  pathEntity.Title,
				},
				Finger: results,
				URI:    fullURL,
			})
		}
	}
}

func (rt *Runtime) checkPath(
	path string,
	webPath structs.UrlPathEntity,
	port int,
	protocol string,
	banner string,
	cert string,
) []string {
	body := rt.body(webPath.Hash)
	header := rt.header(webPath.HeaderHashString)

	var results []string
	for _, finger := range rt.FingerprintDB {
		if ddfinger.SingleCheck(
			finger,
			protocol,
			header,
			body,
			webPath.Server,
			webPath.Title,
			cert,
			port,
			path,
			webPath.Hash,
			webPath.IconHash,
			webPath.StatusCode,
			webPath.ContentType,
			banner,
		) {
			results = append(results, finger.ProductName)
		}
	}

	return dedupe(results)
}

func (rt *Runtime) banner(key string) string {
	return rt.readMap(rt.BannerHMap, key)
}

func (rt *Runtime) body(key string) string {
	return rt.readMap(rt.BodyHMap, key)
}

func (rt *Runtime) header(key string) string {
	return rt.readMap(rt.HeaderHMap, key)
}

func (rt *Runtime) readMap(hm *hybrid.HybridMap, key string) string {
	if hm == nil || key == "" {
		return ""
	}

	value, ok := hm.Get(key)
	if !ok {
		return ""
	}
	return string(value)
}

func splitHostPort(hostPort string) []string {
	return strings.Split(hostPort, ":")
}

func dedupe(input []string) []string {
	if len(input) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(input))
	result := make([]string, 0, len(input))
	for _, item := range input {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}
