package gopocs

import (
	"bufio"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/TokEat/argus/scanner/ddout"
	"github.com/TokEat/argus/scanner/structs"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
)

//go:embed dict/machineKeys.txt
var defaultMachineKeys string

type viewstateKey struct {
	validationKey string // hex or ascii key used for HMAC validation
}

type vsAlgo struct {
	name string
	size int
}

var vsAlgos = []vsAlgo{
	{name: "HMACSHA512", size: 64},
	{name: "HMACSHA384", size: 48},
	{name: "HMACSHA256", size: 32},
	{name: "SHA1", size: 20},
	{name: "MD5", size: 16},
}

func ViewStateKeyCheck(info *structs.HostInfo) {
	urlStr := info.Url
	if urlStr == "" {
		gologger.Debug().Msg("[Go][ViewState] empty url, skip")
		return
	}

	gologger.AuditTimeLogger("[Go] [ViewState] detect %v", urlStr)

	vsValue, vsGen, enc, exchange, err := fetchAndExtractViewStateWithEvidence(urlStr)
	if err != nil || vsValue == "" {
		gologger.AuditTimeLogger("[Go] [ViewState] not found: %v (%v)", urlStr, err)
		return
	}

	// 打印 ViewState 关键信息
	pv := vsValue
	if len(pv) > 40 {
		pv = pv[:40] + "..."
	}
	gologger.AuditTimeLogger("[Go] [ViewState] value(prefix): %s len=%d", pv, len(vsValue))

	if vsGen != "" {
		gologger.AuditTimeLogger("[Go] [ViewState] generator detected: %v", vsGen)
	} else {
		gologger.AuditTimeLogger("[Go] [ViewState] generator not present")
	}

	keys := loadMachineKeys()
	gologger.AuditTimeLogger("[Go] [ViewState] loaded %d candidate keys", len(keys))
	if len(keys) == 0 {
		gologger.AuditTimeLogger("[Go] [ViewState] no machine keys available, skip")
		return
	}

	alg, keyHex := bruteViewState(vsValue, vsGen, enc, keys)
	if alg == "" {
		gologger.AuditTimeLogger("[Go] [ViewState] no key matched %v", urlStr)
		return
	}

	show := fmt.Sprintf("Host: %v\nalg: %v\nkey: %v\n", urlStr, alg, keyHex)
	pocResult := structs.GoPocsResultType{
		PocName:     "ASP.NET ViewState Weak Key",
		Security:    "HIGH",
		Target:      urlStr,
		InfoLeft:    show,
		InfoRight:   "",
		Exchanges:   []structs.GoPocExchange{exchange},
		Description: "ViewState validation key can be derived",
		ShowMsg:     fmt.Sprintf("%s\tALG=%s\tKEY=%s", urlStr, alg, keyHex),
	}
	emitOutput(info, ddout.OutputMessage{
		Type:          "GoPoc",
		IP:            "",
		IPs:           nil,
		Port:          "",
		Protocol:      "",
		Web:           ddout.WebInfo{},
		Finger:        nil,
		Domain:        "",
		GoPoc:         pocResult,
		AdditionalMsg: "",
	})

	writeResult(info, pocResult)
}

func fetchAndExtractViewState(u string) (value string, generator string, encrypted bool, err error) {
	value, generator, encrypted, _, err = fetchAndExtractViewStateWithEvidence(u)
	return value, generator, encrypted, err
}

func fetchAndExtractViewStateWithEvidence(u string) (value string, generator string, encrypted bool, exchange structs.GoPocExchange, err error) {
	// GET the page
	req, err := retryablehttp.NewRequest("GET", u, nil)
	if err != nil {
		return "", "", false, structs.GoPocExchange{}, err
	}
	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSpraying)
	resp, err := client.Do(req)
	if err != nil {
		return "", "", false, structs.GoPocExchange{}, err
	}
	defer resp.Body.Close()
	bodyBytes, err := readCompleteGoPocHTTPBody(resp.Body)
	if err != nil {
		return "", "", false, structs.GoPocExchange{}, err
	}
	html := string(bodyBytes)
	exchange = httpGoPocExchange("ASP.NET ViewState weak-key source page", resp.Request, nil, resp, bodyBytes)
	value, generator, encrypted, err = extractViewState(html)
	return value, generator, encrypted, exchange, err
}

func extractViewState(html string) (string, string, bool, error) {
	// 支持单引号/双引号；额外采集 __EVENTVALIDATION 作为可能的修饰符
	vsRe := regexp.MustCompile(`(?i)<input[^>]*name=['\"]__VIEWSTATE['\"][^>]*value=['\"]([^'\"]+)['\"]`)
	genRe := regexp.MustCompile(`(?i)<input[^>]*name=['\"]__VIEWSTATEGENERATOR['\"][^>]*value=['\"]([^'\"]+)['\"]`)
	encRe := regexp.MustCompile(`(?i)<input[^>]*name=['\"]__VIEWSTATEENCRYPTED['\"]`)
	vs := ""
	gen := ""
	enc := false
	if m := vsRe.FindStringSubmatch(html); len(m) == 2 {
		vs = m[1]
	}
	if m := genRe.FindStringSubmatch(html); len(m) == 2 {
		gen = m[1]
	}
	if encRe.FindStringIndex(html) != nil {
		enc = true
	}
	if vs == "" {
		return "", "", false, errors.New("no __VIEWSTATE")
	}
	return vs, gen, enc, nil
}

func bruteViewState(vsBase64 string, generator string, encrypted bool, candidates []viewstateKey) (string, string) {
	// URL-unescape if needed
	if strings.Contains(vsBase64, "%") {
		if u, err := url.QueryUnescape(vsBase64); err == nil {
			vsBase64 = u
		}
	}
	// try standard and raw base64
	raw, err := base64.StdEncoding.DecodeString(vsBase64)
	if err != nil || len(raw) < 16 {
		raw2, err2 := base64.RawStdEncoding.DecodeString(vsBase64)
		if err2 != nil || len(raw2) < 16 {
			return "", ""
		}
		raw = raw2
	}

	mods := [][]byte{nil}
	mg := strings.TrimSpace(generator)
	if mg != "" {
		if b, _ := hexDecodeStringSafe(mg); len(b) > 0 {
			// 原顺序字节
			mods = append(mods, b)
			// 反序字节
			rb := make([]byte, len(b))
			for i := range b {
				rb[len(b)-1-i] = b[i]
			}
			mods = append(mods, rb)
		}
		// 作为ASCII字符串尝试
		mods = append(mods, []byte(strings.ToUpper(mg)))
		mods = append(mods, []byte(strings.ToLower(mg)))
	}

	for _, algo := range vsAlgos {
		if len(raw) <= algo.size {
			continue
		}
		baseData := raw[:len(raw)-algo.size]
		macProvided := raw[len(raw)-algo.size:]
		// 尝试两种数据变体：原始、原始+0x00 分隔
		dataVariants := [][]byte{baseData, append(append([]byte{}, baseData...), 0x00)}
		for _, k := range candidates {
			kbs := candidateKeyBytes(k.validationKey)
			if len(kbs) == 0 {
				continue
			}
			for _, mod := range mods {
				for _, d := range dataVariants {
					if equalMAC(algo.name, kbs, mod, d, macProvided) {
						return algo.name, strings.ToUpper(k.validationKey)
					}
				}
			}
		}
	}
	return "", ""
}

func equalMAC(algo string, key []byte, modifier []byte, data []byte, macProvided []byte) bool {
	var mac hashLike
	switch algo {
	case "HMACSHA512":
		mac = hmac.New(sha512.New, key)
	case "HMACSHA384":
		mac = hmac.New(sha512.New384, key)
	case "HMACSHA256":
		mac = hmac.New(sha256.New, key)
	case "SHA1":
		mac = hmac.New(sha1.New, key)
	case "MD5":
		mac = hmac.New(md5.New, key)
	default:
		return false
	}
	mac.Write(data)
	if len(modifier) > 0 {
		mac.Write(modifier)
	}
	computed := mac.Sum(nil)
	return len(computed) == len(macProvided) && hmac.Equal(computed, macProvided)
}

type hashLike interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

func candidateKeyBytes(k string) []byte {
	// prefer hex, fallback ascii
	if b, err := hexDecodeStringSafe(k); err == nil && len(b) > 0 {
		return b
	}
	return []byte(k)
}

func hexDecodeStringSafe(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty")
	}
	// normalize: remove commas/colons/spaces
	replacer := strings.NewReplacer(",", "", ":", "", " ", "")
	s = replacer.Replace(s)
	// require even-length
	if len(s)%2 != 0 {
		return nil, errors.New("odd length")
	}
	dec := make([]byte, len(s)/2)
	for i := 0; i < len(dec); i++ {
		var v byte
		a := fromHexChar(s[2*i])
		b := fromHexChar(s[2*i+1])
		if a == 255 || b == 255 {
			return nil, errors.New("non-hex")
		}
		v = a<<4 | b
		dec[i] = v
	}
	return dec, nil
}

func fromHexChar(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 255
	}
}

func loadMachineKeys() []viewstateKey {
	var lines []string
	// external overrides (aggregate)
	candidates := []string{
		"config/dict/machineKeys.txt",
		"test/machineKeys.txt",
	}
	for _, p := range candidates {
		if !fileExists(p) {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		s := bufio.NewScanner(f)
		for s.Scan() {
			lines = append(lines, s.Text())
		}
		_ = f.Close()
	}
	if len(lines) == 0 {
		// fallback to embedded
		defaultMachineKeys = strings.ReplaceAll(defaultMachineKeys, "\r\n", "\n")
		lines = strings.Split(defaultMachineKeys, "\n")
	}
	var ks []viewstateKey
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		// format: ValidationKeyHex,DecryptionKeyHex (we use the first)
		parts := strings.Split(ln, ",")
		if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
			continue
		}
		ks = append(ks, viewstateKey{validationKey: strings.TrimSpace(parts[0])})
	}
	return ks
}
