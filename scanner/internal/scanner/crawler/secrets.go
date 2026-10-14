package crawler

import (
	"regexp"
	"strings"
)

// 敏感信息预筛的 secret/凭据模式。分两类：
//  1. provider 前缀模式（AKIA/ghp_/JWT/PEM 等）——近零误报，先行并标记 span；
//  2. 通用赋值模式（key[:|=]value）——误报较高，值须过过滤器，且跳过已标记 span。
// 仅作召回，精确判定/去重交给服务端 AI。
var (
	awsKeyRe      = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	googleKeyRe   = regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)
	githubTokenRe = regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}`)
	slackTokenRe  = regexp.MustCompile(`xox[baprs]-[A-Za-z0-9\-]{10,}`)
	jwtRe         = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`)
	pemPrivateRe  = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)

	usernameAssignRe = regexp.MustCompile(`(?i)\b(?:username|user|login|account|uid|userid|accountname)\s*[:=]\s*["']?([A-Za-z0-9._\-]{3,32})["']?`)
	passwordAssignRe = regexp.MustCompile(`(?i)\b(?:passwd|password|pwd)\s*[:=]\s*["']?([^\s"']{6,64})["']?`)
	apikeyAssignRe   = regexp.MustCompile(`(?i)\b(?:api[_-]?key|accesskey|access_key|appkey|app_key)\s*[:=]\s*["']?([0-9A-Za-z_\-]{12,64})["']?`)
	tokenAssignRe    = regexp.MustCompile(`(?i)\b(?:token|access_token|auth_token|sessiontoken|bearer)\s*[:=]\s*["']?([0-9A-Za-z_\-\.=]{10,128})["']?`)
	secretAssignRe   = regexp.MustCompile(`(?i)\b(?:secret|appsecret|app_secret|client_secret|clientsecret|private_key)\s*[:=]\s*["']?([0-9A-Za-z_\-/+]{8,128})["']?`)

	placeholderRe = regexp.MustCompile(`(?i)(your|my_|_my|xxx|changeme|change_me|placeholder|example|sample|todo|\$\{|<|>)`)
)

// sensitiveScan 对页面/JS 文本做敏感信息预筛，返回命中（含上下文 snippet）。
// 两阶段：provider 前缀直接定型 → 通用赋值（过滤 + span 排除）→ email/phone/idcard。
func sensitiveScan(body string) []SensitiveHit {
	if body == "" {
		return nil
	}
	var hits []SensitiveHit
	var claimed [][2]int

	provider := []struct {
		re   *regexp.Regexp
		kind string
	}{
		{awsKeyRe, "apikey"},
		{googleKeyRe, "apikey"},
		{githubTokenRe, "token"},
		{slackTokenRe, "token"},
		{jwtRe, "token"},
		{pemPrivateRe, "secret"},
	}
	for _, p := range provider {
		for _, loc := range p.re.FindAllStringIndex(body, -1) {
			claimed = append(claimed, [2]int{loc[0], loc[1]})
			hits = append(hits, SensitiveHit{
				Kind:    p.kind,
				Value:   truncate(body[loc[0]:loc[1]], 200),
				Snippet: snippet(body, loc[0], loc[1], snippetPad),
			})
		}
	}

	generic := []struct {
		re   *regexp.Regexp
		kind string
		ok   func(string) bool
	}{
		{usernameAssignRe, "username", usernameValueOK},
		{passwordAssignRe, "account", func(v string) bool { return credValueOK(v) }},
		{apikeyAssignRe, "apikey", func(v string) bool { return credValueOK(v) }},
		{tokenAssignRe, "token", func(v string) bool { return credValueOK(v) }},
		{secretAssignRe, "secret", func(v string) bool { return credValueOK(v) }},
	}
	for _, g := range generic {
		for _, m := range g.re.FindAllStringSubmatchIndex(body, -1) {
			if m[2] < 0 || m[3] < 0 {
				continue
			}
			// span 排除：命中区与 provider 已 claimed 区重叠则跳过，避免 token=eyJ... 双发。
			if overlapsSpans(claimed, m[0], m[1]) {
				continue
			}
			value := body[m[2]:m[3]]
			if !g.ok(value) {
				continue
			}
			claimed = append(claimed, [2]int{m[0], m[1]})
			hits = append(hits, SensitiveHit{
				Kind:    g.kind,
				Value:   truncate(value, 200),
				Snippet: snippet(body, m[0], m[1], snippetPad),
			})
		}
	}

	for _, item := range []struct {
		re   *regexp.Regexp
		kind string
	}{
		{emailRe, "email"},
		{phoneRe, "phone"},
		{idcardRe, "idcard"},
	} {
		for _, loc := range item.re.FindAllStringIndex(body, -1) {
			hits = append(hits, SensitiveHit{
				Kind:    item.kind,
				Value:   truncate(body[loc[0]:loc[1]], 200),
				Snippet: snippet(body, loc[0], loc[1], snippetPad),
			})
		}
	}
	return hits
}

// credValueOK 通用凭据值的误报过滤器：长度、占位符、全同字符、字符类数。
func credValueOK(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) < 6 {
		return false
	}
	if placeholderRe.MatchString(v) || allSameChar(v) || charsetClasses(v) < 2 {
		return false
	}
	return true
}

// usernameValueOK 用户名专属规则（比 secret 宽松：用户名常单字符类、可较短）：
// 须含字母、非纯数字、不含 @（邮箱归 email 类）、非占位符、非全同字符。
func usernameValueOK(v string) bool {
	if strings.Contains(v, "@") {
		return false
	}
	if placeholderRe.MatchString(v) || allSameChar(v) {
		return false
	}
	hasLetter := false
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLetter = true
			break
		}
	}
	return hasLetter
}

// charsetClasses 统计值包含的字符类数（小写/大写/数字/符号）。
func charsetClasses(v string) int {
	var lower, upper, digit, sym bool
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			sym = true
		}
	}
	n := 0
	if lower {
		n++
	}
	if upper {
		n++
	}
	if digit {
		n++
	}
	if sym {
		n++
	}
	return n
}

func allSameChar(v string) bool {
	if v == "" {
		return false
	}
	c := v[0]
	for i := 1; i < len(v); i++ {
		if v[i] != c {
			return false
		}
	}
	return true
}

// overlapsSpans 判断 [start,end) 是否与任一已标记 span 重叠。
func overlapsSpans(spans [][2]int, start, end int) bool {
	for _, s := range spans {
		if start < s[1] && end > s[0] {
			return true
		}
	}
	return false
}
